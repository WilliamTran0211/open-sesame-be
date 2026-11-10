from dataclasses import dataclass
from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.common.enum import MFAMethod, VerificationPurpose
from app.common.error_message import ErrorMessage
from app.core.config import get_settings
from app.core.exception import (
    ConflictError,
    InvalidGrantError,
    NotFoundError,
    RateLimitError,
    ValidationError,
)
from app.core.redis import RedisClient
from app.core.security import RecoveryCodeHelper, TokenHelper, TotpHelper
from app.models.user import User
from app.models.user_mfa_method import UserMfaMethod
from app.repository.user import UserRepository
from app.repository.user_mfa_method import UserMfaMethodRepository
from app.services.email import EmailServices
from app.services.otp import OTPService

MFA_METHOD_ORDER = [MFAMethod.TOTP, MFAMethod.EMAIL]
TOTP_SETUP_TTL = 300
EMAIL_SETUP_TTL = 120
EMAIL_CODE_TTL = 300  # login and disable codes

MFA_CHALLENGE_TTL = 300
MFA_CHALLENGE_MAX_ATTEMPTS = 5
MFA_CHALLENGE_EMAIL_COOLDOWN = 30  # seconds between login emails for one challenge

def _totp_setup_key(user_id: UUID | str) -> str:
    return f"mfa_setup_totp:{user_id}"


def _challenge_key(challenge_id: str) -> str:
    return f"mfa_challenge:{challenge_id}"


def _challenge_attempts_key(challenge_id: str) -> str:
    return f"mfa_challenge_attempts:{challenge_id}"


def _challenge_email_cooldown_key(challenge_id: str) -> str:
    return f"mfa_challenge_email_cooldown:{challenge_id}"


@dataclass
class MfaSetupResult:
    method: MFAMethod
    secret: Optional[str] = None
    provisioning_uri: Optional[str] = None


@dataclass
class MfaChallenge:
    challenge_id: str
    mfa_method: MFAMethod
    mfa_methods: List[MFAMethod]


@dataclass
class PassedMfaChallenge:
    """What a passed login challenge hands back, so the caller can open the session."""

    user: User
    ip_address: str
    user_agent: str


class MfaService:
    def __init__(
        self,
        db: AsyncSession,
        redis_client: RedisClient,
        otp_services: OTPService,
        email_services: Optional[EmailServices] = None,
    ):
        self.repository = UserMfaMethodRepository(db)
        self.user_repository = UserRepository(db)
        self._redis = redis_client
        self._otp_services = otp_services
        self._email_services = email_services

    async def list_methods(self, user_id: UUID) -> List[MFAMethod]:
        return [row.method for row in await self._list_rows(user_id)]

    async def setup(self, user: User, method: MFAMethod) -> MfaSetupResult:
        if method in await self.list_methods(user.id):
            raise ConflictError(ErrorMessage.MFA_METHOD_ALREADY_ENABLED)

        if method == MFAMethod.TOTP:
            secret = TotpHelper.generate_secret()
            await self._redis.setex(_totp_setup_key(user.id), TOTP_SETUP_TTL, secret)
            return MfaSetupResult(
                method=MFAMethod.TOTP,
                secret=secret,
                provisioning_uri=TotpHelper.get_provisioning_uri(
                    user.email, secret, get_settings().app_name
                ),
            )

        # send email
        code = await self._new_email_code(user, EMAIL_SETUP_TTL)
        if self._email_services:
            await self._email_services.send_mfa_setup_code(user.email, code)
        return MfaSetupResult(method=MFAMethod.EMAIL)

    async def confirm(self, user: User, method: MFAMethod, code: str) -> List[str]:
        enabled = await self.list_methods(user.id)
        if method in enabled:
            raise ConflictError(ErrorMessage.MFA_METHOD_ALREADY_ENABLED)

        secret = None
        if method == MFAMethod.TOTP:
            secret = await self._redis.get(_totp_setup_key(user.id))
            if not secret:
                raise ValidationError(ErrorMessage.MFA_SETUP_NOT_STARTED)
            if not TotpHelper.verify_code(secret, code):
                raise ValidationError(ErrorMessage.INVALID_MFA_CODE)
            await self._redis.delete(_totp_setup_key(user.id))
        elif not await self._verify_email_code(user, code):
            raise ValidationError(ErrorMessage.INVALID_MFA_CODE)

        await self.repository.create(user_id=user.id, method=method, secret=secret)

        raw_codes: List[str] = []
        if not enabled:
            raw_codes, hashes = RecoveryCodeHelper.generate()
            await self.user_repository.update(user.id, mfa_recovery_codes=hashes)
        return raw_codes

    async def request_disable_code(self, user: User) -> None:
        if not await self.list_methods(user.id):
            raise ValidationError(ErrorMessage.MFA_NOT_ENABLED)
        code = await self._new_email_code(user, EMAIL_CODE_TTL)
        if self._email_services:
            await self._email_services.send_mfa_disable_code(user.email, code)

    async def disable(self, user: User, method: MFAMethod, code: str) -> None:
        enabled = await self.list_methods(user.id)
        if method not in enabled:
            raise ValidationError(ErrorMessage.MFA_METHOD_NOT_ENABLED)
        if not await self._verify_email_code(user, code):
            raise ValidationError(ErrorMessage.INVALID_MFA_CODE)

        await self.repository.delete_by_user_method(user.id, method)
        if enabled == [method]:
            await self.user_repository.update(user.id, mfa_recovery_codes=[])

    async def verify_login_code(self, user: User, code: str) -> bool:
        for row in await self._list_rows(user.id):
            if await self._verify_row_code(user, row, code):
                await self.repository.mark_used(row.id)
                return True

        remaining = RecoveryCodeHelper.consume(user.mfa_recovery_codes, code)
        if remaining is not None:
            await self.user_repository.update(user.id, mfa_recovery_codes=remaining)
            return True

        return False

    async def send_login_code(self, user: User) -> None:
        if MFAMethod.EMAIL in await self.list_methods(user.id):
            code = await self._new_email_code(user, EMAIL_CODE_TTL)
            if self._email_services:
                await self._email_services.send_mfa_code(user.email, code)

    async def start_login_challenge(
        self, user: User, ip_address: str, user_agent: str
    ) -> Optional[MfaChallenge]:
        """
        return None if user has no 2FA.
        OR stores a challenge with TTL and send code.
        """
        methods = await self.list_methods(user.id)
        if not methods:
            return None

        challenge_id = TokenHelper.generate()
        await self._redis.setex(
            _challenge_key(challenge_id),
            MFA_CHALLENGE_TTL,
            f"{user.id}|{ip_address}|{user_agent}",
        )
        if methods[0] == MFAMethod.EMAIL:
            await self._send_challenge_email(challenge_id, user)
        return MfaChallenge(
            challenge_id=challenge_id, mfa_method=methods[0], mfa_methods=methods
        )

    async def send_challenge_email(self, challenge_id: str) -> None:
        user, _, _ = await self._load_challenge(challenge_id)
        await self._send_challenge_email(challenge_id, user)

    async def verify_challenge(
        self, challenge_id: str, code: str
    ) -> PassedMfaChallenge:
        """Check a login code against the challenge. Too many wrong codes
        kills the challenge and the user has to log in again."""
        user, ip_address, user_agent = await self._load_challenge(challenge_id)

        attempts_key = _challenge_attempts_key(challenge_id)
        attempts = await self._redis.incr(attempts_key)
        if attempts == 1:
            await self._redis.expire(attempts_key, MFA_CHALLENGE_TTL)
        if attempts > MFA_CHALLENGE_MAX_ATTEMPTS:
            await self._clear_challenge(challenge_id)
            raise InvalidGrantError(ErrorMessage.MFA_CHALLENGE_EXPIRED)

        if not await self.verify_login_code(user, code):
            raise ValidationError(ErrorMessage.INVALID_MFA_CODE)

        await self._clear_challenge(challenge_id)
        return PassedMfaChallenge(
            user=user, ip_address=ip_address, user_agent=user_agent
        )

    async def _load_challenge(self, challenge_id: str) -> Tuple[User, str, str]:
        raw = await self._redis.get(_challenge_key(challenge_id))
        if not raw:
            raise InvalidGrantError(ErrorMessage.MFA_CHALLENGE_EXPIRED)
        user_id, ip_address, user_agent = raw.split("|", 2)
        user = await self.user_repository.get(user_id)
        if not user or not user.is_active:
            raise NotFoundError(ErrorMessage.NOT_FOUND)
        return user, ip_address, user_agent

    async def _send_challenge_email(self, challenge_id: str, user: User) -> None:
        cooldown_key = _challenge_email_cooldown_key(challenge_id)
        if not await self._redis.acquire_lock(
            cooldown_key, MFA_CHALLENGE_EMAIL_COOLDOWN
        ):
            remaining = await self._redis.ttl(cooldown_key)
            raise RateLimitError(
                ErrorMessage.RATE_LIMITED,
                retry_after=remaining
                if remaining > 0
                else MFA_CHALLENGE_EMAIL_COOLDOWN,
            )
        await self.send_login_code(user)

    async def _clear_challenge(self, challenge_id: str) -> None:
        await self._redis.delete(_challenge_key(challenge_id))
        await self._redis.delete(_challenge_attempts_key(challenge_id))
        await self._redis.delete(_challenge_email_cooldown_key(challenge_id))

    async def _list_rows(self, user_id: UUID) -> List[UserMfaMethod]:
        rows = await self.repository.list_by_user(user_id)
        order = {m: i for i, m in enumerate(MFA_METHOD_ORDER)}
        return sorted(rows, key=lambda r: order.get(r.method, len(order)))

    async def _verify_row_code(self, user: User, row: UserMfaMethod, code: str) -> bool:
        if row.method == MFAMethod.TOTP:
            return bool(row.secret) and TotpHelper.verify_code(row.secret, code)
        if row.method == MFAMethod.EMAIL:
            return await self._verify_email_code(user, code)
        return False

    async def _new_email_code(self, user: User, ttl: int) -> str:
        """Setup, login and disable share one email OTP slot: a new code
        replaces any earlier one."""
        return await self._otp_services.generate(
            user.id, VerificationPurpose.TWO_FACTOR_AUTH, ttl=ttl
        )

    async def _verify_email_code(self, user: User, code: str) -> bool:
        return await self._otp_services.verify(
            user.id, VerificationPurpose.TWO_FACTOR_AUTH, code
        )
