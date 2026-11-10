import uuid
from typing import Annotated

from fastapi import BackgroundTasks, Cookie, Depends, Request

from app.common.error_message import ErrorMessage
from app.core.config import get_email_settings
from app.core.deps import RedisDep
from app.core.exception import ForbiddenError, UnauthorizedError
from app.db.deps import DBDep
from app.models.client import OAuthClient
from app.models.user import User
from app.services.access_token import TokenService, get_token_service
from app.services.auth import AuthService
from app.services.client import OAuthClientService
from app.services.email import EmailServices
from app.services.mfa import MfaService
from app.services.oauth_consent import OAuthConsentService
from app.services.otp import OTPService
from app.services.refresh_token import RefreshTokenServices
from app.services.scope import ScopeServices
from app.services.user import UserService
from app.services.user_session import UserSessionService


def get_otp_service(redis_client: RedisDep) -> OTPService:
    return OTPService(redis_client)


def get_email_services(background_tasks: BackgroundTasks) -> EmailServices:
    return EmailServices(get_email_settings(), background_tasks)


def get_user_services(
    db: DBDep,
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    email_service: Annotated[EmailServices, Depends(get_email_services)],
) -> UserService:
    return UserService(db, otp_service, email_service)


def get_mfa_services(
    db: DBDep,
    redis_client: RedisDep,
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    email_service: Annotated[EmailServices, Depends(get_email_services)],
) -> MfaService:
    return MfaService(db, redis_client, otp_service, email_service)


def get_user_session_services(
    db: DBDep,
    redis_client: RedisDep,
) -> UserSessionService:
    return UserSessionService(db, redis_client)


def get_refresh_token_services(db: DBDep) -> RefreshTokenServices:
    return RefreshTokenServices(db)


def get_auth_services(
    db: DBDep,
    redis_client: RedisDep,
    user_services: Annotated[UserService, Depends(get_user_services)],
    mfa_services: Annotated[MfaService, Depends(get_mfa_services)],
    token_services: Annotated[
        RefreshTokenServices, Depends(get_refresh_token_services)
    ],
    access_token_service: Annotated[TokenService, Depends(get_token_service)],
) -> AuthService:
    session_services = UserSessionService(db, redis_client)
    return AuthService(
        db,
        user_services,
        mfa_services,
        session_services,
        token_services,
        access_token_service,
    )


def get_scope_services(db: DBDep) -> ScopeServices:
    return ScopeServices(db)


def get_oauth_consent_services(
    db: DBDep,
    token_services: Annotated[
        RefreshTokenServices, Depends(get_refresh_token_services)
    ],
) -> OAuthConsentService:
    return OAuthConsentService(db, token_services)


def get_client_services(
    db: DBDep,
    token_services: Annotated[
        RefreshTokenServices, Depends(get_refresh_token_services)
    ],
    scope_services: Annotated[ScopeServices, Depends(get_scope_services)],
) -> OAuthClientService:
    return OAuthClientService(db, token_services, scope_services)


async def get_current_user(
    request: Request,
    user_service: Annotated[UserService, Depends(get_user_services)],
    user_session_services: Annotated[
        UserSessionService, Depends(get_user_session_services)
    ],
    session_id: Annotated[str | None, Cookie()] = None,
) -> User:
    payload = request.state.token_payload
    if payload:
        return await user_service.get_active_user(uuid.UUID(payload.sub))

    if session_id:
        return await user_session_services.get_user_session(session_id)

    raise UnauthorizedError(ErrorMessage.UNAUTHORIZED)


async def require_token(
    request: Request,
    user_service: Annotated[UserService, Depends(get_user_services)],
) -> User:
    payload = request.state.token_payload
    if not payload:
        raise UnauthorizedError(ErrorMessage.UNAUTHORIZED)
    return await user_service.get_active_user(uuid.UUID(payload.sub))


async def require_session(
    user_session_services: Annotated[
        UserSessionService, Depends(get_user_session_services)
    ],
    session_id: Annotated[str | None, Cookie()] = None,
) -> User:
    if not session_id:
        raise UnauthorizedError(ErrorMessage.UNAUTHORIZED)
    return await user_session_services.get_user_session(session_id)


async def require_superuser(
    current_user: Annotated[User, Depends(require_session)],
) -> User:
    if not current_user.is_superuser:
        raise ForbiddenError(ErrorMessage.ACCESS_DENIED)
    return current_user


async def get_owned_client(
    client_id: str,
    current_user: Annotated[User, Depends(require_session)],
    client_services: Annotated[OAuthClientService, Depends(get_client_services)],
) -> OAuthClient:
    client = await client_services.get_client_by_id(client_id)
    if client.owner_id != current_user.id and not current_user.is_superuser:
        raise ForbiddenError(ErrorMessage.ACCESS_DENIED)
    return client


OtpServicesDep = Annotated[OTPService, Depends(get_otp_service)]
EmailServicesDep = Annotated[EmailServices, Depends(get_email_services)]
UserServicesDep = Annotated[UserService, Depends(get_user_services)]
MfaServicesDep = Annotated[MfaService, Depends(get_mfa_services)]

AuthServicesDep = Annotated[AuthService, Depends(get_auth_services)]
UserSessionServicesDep = Annotated[
    UserSessionService, Depends(get_user_session_services)
]
OAuthClientServiceDep = Annotated[OAuthClientService, Depends(get_client_services)]
ScopeServicesDep = Annotated[ScopeServices, Depends(get_scope_services)]
OAuthConsentServicesDep = Annotated[
    OAuthConsentService, Depends(get_oauth_consent_services)
]

CurrentUserDep = Annotated[User, Depends(get_current_user)]
RequireTokenDep = Annotated[User, Depends(require_token)]
RequireSessionDep = Annotated[User, Depends(require_session)]
RequireSuperuserDep = Annotated[User, Depends(require_superuser)]
OwnedClientDep = Annotated[OAuthClient, Depends(get_owned_client)]
