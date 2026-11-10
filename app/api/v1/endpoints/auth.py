import logging
from typing import Annotated

from fastapi import APIRouter, Cookie, Request, Response, status

from app.api.deps import AuthServicesDep, MfaServicesDep, RequireSessionDep
from app.common.error_message import ErrorMessage
from app.core.rate_limit import rate_limit
from app.core.config import get_settings
from app.core.exception import ForbiddenError
from app.schemas.mfa import (
    MfaChallengeEmailSchema,
    MfaChallengeResponseSchema,
    MfaVerifySchema,
)
from app.schemas.session import SessionResponseSchema
from app.schemas.user import UserLogin, UserResponseSchema
from app.services.mfa import MfaChallenge

router = APIRouter()

logger = logging.getLogger("open_sesame_logger")


@router.get("/")
def read_root():
    logger.debug("Root endpoint accessed")
    return {"message": "Open Sesame, Authentication!"}


def _set_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=get_settings().session_max_age_seconds,
    )


@router.post(
    "/login", dependencies=[rate_limit("login", identifier_field="email")]
)
async def login(
    body: UserLogin,
    request: Request,
    response: Response,
    auth_service: AuthServicesDep,
):
    data = {
        "email": body.email,
        "password": body.password,
        "ip_address": request.client.host,
        "user_agent": request.headers.get("user-agent"),
    }

    result = await auth_service.login(**data)

    if isinstance(result, MfaChallenge):
        return MfaChallengeResponseSchema(
            challenge_id=result.challenge_id,
            mfa_method=result.mfa_method,
            mfa_methods=result.mfa_methods,
        )

    user, session = result
    _set_session_cookie(response, session.session_id)
    return UserResponseSchema.model_validate(user)


@router.post(
    "/login/2fa",
    dependencies=[rate_limit("login-2fa", identifier_field="challenge_id")],
)
async def login_2fa(
    body: MfaVerifySchema,
    response: Response,
    auth_service: AuthServicesDep,
):
    user, session = await auth_service.complete_mfa_challenge(
        body.challenge_id, body.code
    )
    _set_session_cookie(response, session.session_id)
    return UserResponseSchema.model_validate(user)


@router.post(
    "/login/2fa/email",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        rate_limit(
            "login-2fa-email",
            identifier_field="challenge_id",
            limit=3,
            window_seconds=300,
        )
    ],
)
async def login_2fa_email(
    body: MfaChallengeEmailSchema,
    mfa_services: MfaServicesDep,
):
    await mfa_services.send_challenge_email(body.challenge_id)


@router.post("/logout")
async def logout(
    session_id: Annotated[str | None, Cookie()],
    auth_service: AuthServicesDep,
):
    if not session_id:
        raise ForbiddenError(ErrorMessage.ACCESS_DENIED)

    await auth_service.logout(session_id)
    return {"message": "success"}


@router.get("/sessions", response_model=list[SessionResponseSchema])
async def list_sessions(
    current_user: RequireSessionDep,
    auth_service: AuthServicesDep,
):
    return await auth_service.list_sessions(current_user.id)


@router.post("/sessions/revoke-all")
async def revoke_all_sessions(
    current_user: RequireSessionDep,
    auth_service: AuthServicesDep,
):
    await auth_service.revoke_all_sessions(current_user.id)
    return {"message": "success"}
