from fastapi import APIRouter

from app.api.deps import MfaServicesDep, RequireSessionDep
from app.common.enum import MFAMethod
from app.core.rate_limit import rate_limit_by_user
from app.schemas.mfa import (
    MfaConfirmResponseSchema,
    MfaConfirmSchema,
    MfaDisableSchema,
    MfaSetupRequestSchema,
    MfaSetupResponseSchema,
    MfaStatusSchema,
)

router = APIRouter()


@router.get("", response_model=MfaStatusSchema)
async def get_mfa_status(
    mfa_services: MfaServicesDep,
    current_user: RequireSessionDep,
):
    methods = await mfa_services.list_methods(current_user.id)
    return MfaStatusSchema(enabled=bool(methods), methods=methods)


@router.post(
    "/setup",
    response_model=MfaSetupResponseSchema,
    dependencies=[rate_limit_by_user("2fa-setup", limit=5, window_seconds=300)],
)
async def setup_mfa(
    data: MfaSetupRequestSchema,
    mfa_services: MfaServicesDep,
    current_user: RequireSessionDep,
):
    """
    totp: returns a fresh QR exp: 5 minutes
    email: sends a code exp: 2 minutes
    Call again to renew
    """
    result = await mfa_services.setup(current_user, MFAMethod(data.method))
    return MfaSetupResponseSchema(
        method=result.method.value,
        secret=result.secret,
        provisioning_uri=result.provisioning_uri,
    )


@router.post(
    "/confirm",
    response_model=MfaConfirmResponseSchema,
    dependencies=[rate_limit_by_user("2fa-confirm")],
)
async def confirm_mfa(
    data: MfaConfirmSchema,
    mfa_services: MfaServicesDep,
    current_user: RequireSessionDep,
):
    recovery_codes = await mfa_services.confirm(
        current_user, MFAMethod(data.method), data.code
    )
    return MfaConfirmResponseSchema(recovery_codes=recovery_codes)


@router.post(
    "/disable/request-code",
    dependencies=[
        rate_limit_by_user("2fa-disable-request-code", limit=5, window_seconds=300)
    ],
)
async def request_mfa_disable_code(
    mfa_services: MfaServicesDep,
    current_user: RequireSessionDep,
):
    await mfa_services.request_disable_code(current_user)
    return {"message": "success"}


@router.post(
    "/disable",
    dependencies=[rate_limit_by_user("2fa-disable")],
)
async def disable_mfa(
    data: MfaDisableSchema,
    mfa_services: MfaServicesDep,
    current_user: RequireSessionDep,
):
    await mfa_services.disable(current_user, MFAMethod(data.method), data.code)
    return {"message": "success"}
