from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.common.enum import MFAMethod, VerificationPurpose
from app.common.error_message import ErrorMessage
from app.core import security
from app.core.exception import (
    ConflictError,
    NotFoundError,
    RateLimitError,
    UnauthorizedError,
    ValidationError,
)
from app.models.user import User
from app.repository.user import UserRepository
from app.schemas.user import CreateUserSchema, UpdateUserSchema
from app.services.email import EmailServices
from app.services.mfa import MFAService
from app.services.otp import OTPService


@dataclass
class MfaSetupResult:
    method: MFAMethod
    secret: Optional[str] = None
    provisioning_uri: Optional[str] = None


class UserService:
    DUMMY_HASH = "$2b$12$eImiTXuWVxfM37uY4JANjQ" + "x" * 31

    def __init__(
        self,
        db: AsyncSession,
        otp_services: OTPService = None,
        email_services: EmailServices = None,
    ):
        self.repository = UserRepository(db)
        self._otp_services = otp_services
        self._email_services = email_services

    async def get(self, id: str) -> User:
        return await self.repository.get(id)

    async def get_multi(
        self, skip: int = 0, limit: int = 100, filters: Optional[Dict[str, Any]] = None
    ) -> List[User]:
        return await self.repository.get_all(skip=skip, limit=limit, filters=filters)

    async def get_active_user(self, id: UUID | str) -> User:
        user = await self.repository.get(str(id))
        if not user or not user.is_active:
            raise NotFoundError(ErrorMessage.NOT_FOUND)
        return user

    async def create_user(self, data: CreateUserSchema) -> tuple[User, str]:
        check_user = await self.repository.get_by_email(data.email)

        if check_user:
            raise ConflictError(ErrorMessage.CONFLICT)

        pwd_hash = security.PasswordHelper.hash(data.password)

        user = await self.repository.create(
            email=data.email.lower(), hashed_password=pwd_hash, full_name=data.full_name
        )

        # gen OTP for verify
        otp_code = await self._otp_services.generate(
            user.id, purpose=VerificationPurpose.EMAIL_VERIFY
        )

        if self._email_services:
            await self._email_services.send_verify_email(user.email, otp_code)

        return user

    async def update_user(self, user_id: str, data: UpdateUserSchema) -> User:
        check_user = await self.repository.get(user_id)

        if not check_user:
            raise NotFoundError(ErrorMessage.NOT_FOUND)

        update_data = data.model_dump(exclude_none=True)

        if "email" in update_data:
            email = update_data["email"].lower()
            if email != check_user.email:
                existing = await self.repository.get_by_email(email)
                if existing:
                    raise ConflictError(ErrorMessage.CONFLICT)
                update_data["email"] = email
                update_data["is_verified"] = False
                update_data["email_verified"] = False
                if self._otp_services:
                    otp_code = await self._otp_services.generate(
                        check_user.id, purpose=VerificationPurpose.EMAIL_VERIFY
                    )
                    if self._email_services:
                        await self._email_services.send_verify_email(email, otp_code)

        if not update_data:
            return check_user

        user = await self.repository.update(check_user.id, **update_data)
        return user

    async def authenticate(self, email: str, password: str) -> User:
        user = await self.repository.get_by_email(email.lower())

        hashed_pwd = user.hashed_password if user else self.DUMMY_HASH

        is_valid = security.PasswordHelper.verify(
            password.encode(), hashed_pwd.encode()
        )

        if not user or not is_valid:
            raise UnauthorizedError(ErrorMessage.UNAUTHORIZED)

        return user

    async def verify_email(self, email: str, otp: str) -> User:
        user = await self.repository.get_by_email(email.lower())

        if not user:
            raise ValidationError(ErrorMessage.INVALID_OTP)

        if user.is_verified:
            return user

        check = await self._otp_services.verify(
            user.id, VerificationPurpose.EMAIL_VERIFY, otp
        )
        if not check:
            raise ValidationError(ErrorMessage.INVALID_OTP)

        return await self.repository.update(
            user.id, email_verified=True, is_verified=True
        )

    async def resend_verification(self, email: str) -> None:
        user = await self.repository.get_by_email(email.lower())

        # Stay silent for unknown or already-verified emails to avoid leaking accounts.
        # EmailServices backgrounds the actual SMTP call, so this branch and the
        # early-return above take the same time — otherwise awaiting SMTP here is
        # a timing side-channel that lets a caller tell real emails from unknown ones.
        if not user or user.is_verified:
            return

        if await self._otp_services.is_rate_limited(
            user.id, VerificationPurpose.EMAIL_VERIFY
        ):
            raise RateLimitError(ErrorMessage.RATE_LIMITED)

        otp_code = await self._otp_services.generate(
            user.id, purpose=VerificationPurpose.EMAIL_VERIFY
        )

        if self._email_services:
            await self._email_services.send_verify_email(user.email, otp_code)

    async def request_password_reset(self, email: str) -> None:
        user = await self.repository.get_by_email(email.lower())

        if not user:
            return

        if await self._otp_services.is_rate_limited(
            user.id, VerificationPurpose.PASSWORD_RESET
        ):
            raise RateLimitError(ErrorMessage.RATE_LIMITED)

        otp_code = await self._otp_services.generate(
            user.id, purpose=VerificationPurpose.PASSWORD_RESET
        )

        if self._email_services:
            await self._email_services.send_reset_password_email(user.email, otp_code)

    async def confirm_password_reset(
        self, email: str, otp: str, new_password: str
    ) -> User:
        user = await self.repository.get_by_email(email.lower())

        if not user:
            raise ValidationError(ErrorMessage.INVALID_OTP)

        check = await self._otp_services.verify(
            user.id, VerificationPurpose.PASSWORD_RESET, otp
        )
        if not check:
            raise ValidationError(ErrorMessage.INVALID_OTP)

        pwd_hash = security.PasswordHelper.hash(new_password)
        return await self.repository.update(user.id, hashed_password=pwd_hash)

    async def setup_mfa(self, user_id: str, method: MFAMethod) -> MfaSetupResult:
        user = await self.repository.get(user_id)
        if not user:
            raise NotFoundError(ErrorMessage.NOT_FOUND)
        if user.mfa_enabled:
            raise ConflictError(ErrorMessage.MFA_ALREADY_ENABLED)

        if method == MFAMethod.TOTP:
            secret = MFAService.generate_secret()
            await self.repository.update(
                user.id, mfa_method=MFAMethod.TOTP, mfa_secret=secret
            )
            provisioning_uri = MFAService.get_provisioning_uri(user.email, secret)
            return MfaSetupResult(
                method=MFAMethod.TOTP, secret=secret, provisioning_uri=provisioning_uri
            )

        # EMAIL
        await self.repository.update(
            user.id, mfa_method=MFAMethod.EMAIL, mfa_secret=None
        )
        await self._send_mfa_email_code(user, setup=True)
        return MfaSetupResult(method=MFAMethod.EMAIL)

    async def confirm_mfa(self, user_id: str, code: str) -> List[str]:
        user = await self.repository.get(user_id)
        if not user:
            raise NotFoundError(ErrorMessage.NOT_FOUND)
        if user.mfa_enabled:
            raise ConflictError(ErrorMessage.MFA_ALREADY_ENABLED)
        if not user.mfa_method:
            raise ValidationError(ErrorMessage.MFA_SETUP_NOT_STARTED)
        if not await self._verify_active_method_code(user, code):
            raise ValidationError(ErrorMessage.INVALID_MFA_CODE)

        raw_codes, hashes = MFAService.generate_recovery_codes()
        await self.repository.update(
            user.id, mfa_enabled=True, mfa_recovery_codes=hashes
        )
        return raw_codes

    async def disable_mfa(self, user_id: str, code: str) -> None:
        user = await self.repository.get(user_id)
        if not user:
            raise NotFoundError(ErrorMessage.NOT_FOUND)
        if not user.mfa_enabled:
            raise ValidationError(ErrorMessage.MFA_NOT_ENABLED)
        if not await self.verify_mfa_code(user, code):
            raise ValidationError(ErrorMessage.INVALID_MFA_CODE)

        await self.repository.update(
            user.id,
            mfa_enabled=False,
            mfa_method=None,
            mfa_secret=None,
            mfa_recovery_codes=[],
        )

    async def request_mfa_code(self, user_id: str) -> None:
        """Send a fresh email OTP — used for EMAIL-method setup confirmation
        resends and before disabling EMAIL-method MFA. No-op for TOTP."""
        user = await self.repository.get(user_id)
        if not user:
            raise NotFoundError(ErrorMessage.NOT_FOUND)
        # Not enabled yet means this is a setup-confirmation resend.
        await self._send_mfa_email_code(user, setup=not user.mfa_enabled)

    async def verify_mfa_code(self, user: User, code: str) -> bool:
        if await self._verify_active_method_code(user, code):
            return True

        remaining = MFAService.consume_recovery_code(user.mfa_recovery_codes, code)
        if remaining is not None:
            await self.repository.update(user.id, mfa_recovery_codes=remaining)
            return True

        return False

    async def send_mfa_code_if_email(self, user: User) -> None:
        """Called on login once an MFA challenge is created — no-op for TOTP,
        since the authenticator app already has the code offline."""
        if user.mfa_method == MFAMethod.EMAIL:
            await self._send_mfa_email_code(user)

    async def _verify_active_method_code(self, user: User, code: str) -> bool:
        if user.mfa_method == MFAMethod.TOTP:
            return MFAService.verify_code(user.mfa_secret, code)
        if user.mfa_method == MFAMethod.EMAIL:
            return await self._otp_services.verify(
                user.id, VerificationPurpose.TWO_FACTOR_AUTH, code
            )
        return False

    async def _send_mfa_email_code(self, user: User, setup: bool = False) -> None:
        otp_code = await self._otp_services.generate(
            user.id, purpose=VerificationPurpose.TWO_FACTOR_AUTH
        )
        if not self._email_services:
            return
        if setup:
            await self._email_services.send_mfa_setup_code(user.email, otp_code)
        else:
            await self._email_services.send_mfa_code(user.email, otp_code)

    async def change_password(
        self, user_id: str, current_password: str, new_password: str
    ):
        user = await self.repository.get(user_id)

        is_valid = security.PasswordHelper.verify(
            current_password.encode(), user.hashed_password
        )

        if not is_valid:
            raise ValidationError("Password mismatch")

        pwd_hash = security.PasswordHelper.hash(new_password)

        user = await self.repository.update(user.id, hashed_password=pwd_hash)
        return user
