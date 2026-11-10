from fastapi import APIRouter, Request

from app.api.deps import (
    CurrentUserDep,
    OAuthClientServiceDep,
    OAuthConsentServicesDep,
    RequireSessionDep,
    RequireSuperuserDep,
    UserServicesDep,
)
from app.common.error_message import ErrorMessage
from app.core.exception import NotFoundError
from app.core.rate_limit import rate_limit
from app.schemas.otp import (
    ConfirmPasswordResetSchema,
    RequestPasswordResetSchema,
    ResendVerificationSchema,
    VerifyEmailSchema,
)
from app.schemas.token import ConsentSummarySchema
from app.schemas.user import (
    ChangePasswordSchema,
    CreateUserSchema,
    UpdateUserSchema,
    UserInfoResponseSchema,
    UserResponseSchema,
)

router = APIRouter()


@router.get("/")
def read_root():
    return {"message": "Open Sesame, User service!"}


@router.get("/me")
async def get_me(current_user: CurrentUserDep, request: Request):
    # Bearer token only gets fields allowed by its scope.
    payload = request.state.token_payload
    if payload is None:
        return UserResponseSchema.model_validate(current_user)

    scopes = set(payload.scope.split())
    return UserInfoResponseSchema(
        sub=current_user.id,
        email=current_user.email if "email" in scopes else None,
        email_verified=current_user.email_verified if "email" in scopes else None,
        name=current_user.full_name if "profile" in scopes else None,
    )


@router.patch("/me", response_model=UserResponseSchema)
async def update_me(
    data: UpdateUserSchema,
    user_services: UserServicesDep,
    current_user: RequireSessionDep,
):
    user = await user_services.update_user(str(current_user.id), data)
    return user


@router.post("/me/change-password")
async def change_password(
    data: ChangePasswordSchema,
    user_services: UserServicesDep,
    current_user: RequireSessionDep,
):
    result = await user_services.change_password(
        user_id=current_user.id,
        current_password=data.current_password,
        new_password=data.new_password,
    )
    return result


@router.get("/me/consents", response_model=list[ConsentSummarySchema])
async def list_my_consents(
    current_user: RequireSessionDep,
    consent_services: OAuthConsentServicesDep,
):
    consents = await consent_services.list_user_consents(current_user.id)
    return [
        ConsentSummarySchema(
            client_id=consent.client.client_id,
            client_name=consent.client.name,
            scopes=consent.scopes,
            granted_at=consent.created_at,
            updated_at=consent.updated_at,
        )
        for consent in consents
    ]


@router.delete("/me/consents/{client_id}")
async def revoke_my_consent(
    client_id: str,
    current_user: RequireSessionDep,
    consent_services: OAuthConsentServicesDep,
    client_services: OAuthClientServiceDep,
):
    client = await client_services.get_client_by_id(client_id)
    revoked = await consent_services.revoke_consent(current_user.id, client.id)
    if not revoked:
        raise NotFoundError(ErrorMessage.NOT_FOUND)
    return {"message": "success"}


@router.post(
    "/register",
    response_model=UserResponseSchema,
    dependencies=[rate_limit("register", identifier_field="email")],
)
async def register(user_data: CreateUserSchema, user_services: UserServicesDep):
    user = await user_services.create_user(user_data)
    return user


@router.post(
    "/reset-password",
    dependencies=[
        rate_limit("reset-password-request", identifier_field="email"),
        rate_limit("reset-password-request-ip"),
    ],
)
async def reset_password(
    data: RequestPasswordResetSchema, user_services: UserServicesDep
):
    await user_services.request_password_reset(data.email)
    return {"message": "success"}


@router.post(
    "/reset-password/confirm",
    response_model=UserResponseSchema,
    dependencies=[rate_limit("reset-password", identifier_field="email")],
)
async def confirm_reset_password(
    data: ConfirmPasswordResetSchema, user_services: UserServicesDep
):
    return await user_services.confirm_password_reset(
        data.email, data.otp, data.new_password
    )


@router.post(
    "/verify",
    response_model=UserResponseSchema,
    dependencies=[rate_limit("verify-email", identifier_field="email")],
)
async def verify_email(data: VerifyEmailSchema, user_services: UserServicesDep):
    user = await user_services.verify_email(data.email, data.otp)
    return user


@router.post(
    "/verify/resend",
    dependencies=[rate_limit("verify-email", identifier_field="email")],
)
async def resend_verification(
    data: ResendVerificationSchema, user_services: UserServicesDep
):
    await user_services.resend_verification(data.email)
    return {"message": "success"}


@router.get("/list", response_model=list[UserResponseSchema])
async def get_user_list(user_services: UserServicesDep, _: RequireSuperuserDep):
    list_users = await user_services.get_multi()
    return list_users
