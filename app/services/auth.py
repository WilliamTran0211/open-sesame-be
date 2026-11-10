from datetime import datetime, timedelta, timezone
from typing import Optional, Union
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.common.enum import ClientType
from app.common.error_message import ErrorMessage
from app.core.exception import (
    EmailNotVerifiedError,
    InvalidGrantError,
    InvalidRequestError,
)
from app.core.security import SecurityHelper, TokenHelper
from app.models.client import OAuthClient
from app.models.user import User
from app.models.user_session import UserSession
from app.repository.authorization_code import AuthorizationCodeRepository
from app.services.access_token import TokenService
from app.services.mfa import MfaChallenge, MfaService
from app.services.refresh_token import RefreshTokenServices
from app.services.user import UserService
from app.services.user_session import UserSessionService


class AuthService:
    def __init__(
        self,
        db: AsyncSession,
        user_services: UserService,
        mfa_services: MfaService,
        session_services: UserSessionService,
        token_services: RefreshTokenServices,
        access_token_service: TokenService,
    ):
        self.user_services = user_services
        self.mfa_services = mfa_services
        self.session_services = session_services
        self.token_services = token_services
        self.access_token_service = access_token_service
        self.auth_code_repo = AuthorizationCodeRepository(db)

    async def login(
        self, email: str, password: str, ip_address: str, user_agent: str
    ) -> Union[tuple[User, UserSession], MfaChallenge]:
        user = await self.user_services.authenticate(email, password)

        if not user.is_verified:
            raise EmailNotVerifiedError(ErrorMessage.EMAIL_NOT_VERIFIED)

        challenge = await self.mfa_services.start_login_challenge(
            user, ip_address, user_agent
        )
        if challenge:
            return challenge

        session = await self.session_services.create_session(
            user.id, ip_address, user_agent
        )
        return user, session

    async def complete_mfa_challenge(
        self, challenge_id: str, code: str
    ) -> tuple[User, UserSession]:
        passed = await self.mfa_services.verify_challenge(challenge_id, code)
        session = await self.session_services.create_session(
            passed.user.id, passed.ip_address, passed.user_agent
        )
        return passed.user, session

    async def logout(self, session_id: str) -> None:
        await self.session_services.terminate_session(session_id)

    async def list_sessions(self, user_id: UUID) -> list:
        return await self.session_services.list_active_sessions(str(user_id))

    async def revoke_all_sessions(self, user_id: UUID) -> None:
        await self.session_services.terminate_all_session(str(user_id))

    async def refresh_token(
        self, raw_token: str, client: OAuthClient
    ) -> tuple[str, str, int]:
        token_hash = TokenHelper.hash(raw_token)
        old_token = await self.token_services.repository.get_by_hash(token_hash)

        if not old_token or old_token.client_id != client.id:
            raise InvalidGrantError("Invalid refresh token")

        raw_refresh, new_token = await self.token_services.rotate_token(
            old_token, client.id, ttl_seconds=client.refresh_token_ttl
        )
        ttl = client.access_token_ttl or self.access_token_service.access_token_expire
        access_token = self.access_token_service.issue_access_token(
            new_token.user_id, client.id, new_token.scope, ttl_seconds=ttl
        )

        return access_token, raw_refresh, ttl

    async def revoke_token(self, raw_token: str) -> None:
        token_hash = TokenHelper.hash(raw_token)
        token = await self.token_services.repository.get_by_hash(token_hash)

        # Per RFC 7009: succeed silently even if the token is unknown/already revoked.
        if token and not token.is_revoked:
            await self.token_services.revoke_chain(token.family_id)

    async def authorize(
        self,
        client: OAuthClient,
        user_id: UUID,
        redirect_uri: str,
        scope: str,
        code_challenge: Optional[str],
    ) -> str:
        if client.client_type == ClientType.PUBLIC or client.require_pkce:
            if not code_challenge:
                raise InvalidRequestError(ErrorMessage.INVALID_REQUEST)

        code = TokenHelper.generate()
        await self.auth_code_repo.create(
            code=code,
            user_id=user_id,
            client_id=client.id,
            scope=scope,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        return code

    async def exchange_authorization_code(
        self,
        client: OAuthClient,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str],
    ) -> tuple[str, str, int]:
        auth_code = await self.auth_code_repo.get_by_code(code)

        if not auth_code or auth_code.client_id != client.id:
            raise InvalidGrantError("Invalid authorization code")
        if auth_code.is_expired or auth_code.is_used:
            raise InvalidGrantError("Invalid authorization code")
        if auth_code.redirect_uri != redirect_uri:
            raise InvalidGrantError("redirect_uri mismatch")

        if auth_code.code_challenge:
            if not code_verifier or not SecurityHelper.verify_pkce(
                code_verifier, auth_code.code_challenge
            ):
                raise InvalidGrantError("Invalid code_verifier")

        consumed = await self.auth_code_repo.mark_used(auth_code.id)
        if not consumed:
            # Race: another request already consumed this code.
            raise InvalidGrantError("Authorization code already used")

        ttl = client.access_token_ttl or self.access_token_service.access_token_expire
        access_token = self.access_token_service.issue_access_token(
            auth_code.user_id, client.id, auth_code.scope, ttl_seconds=ttl
        )
        raw_refresh, _ = await self.token_services.create_token(
            auth_code.user_id,
            client.id,
            scope=auth_code.scope,
            ttl_seconds=client.refresh_token_ttl,
        )

        return access_token, raw_refresh, ttl

    def client_credentials(self):
        pass
