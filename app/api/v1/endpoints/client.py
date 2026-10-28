from fastapi import APIRouter

from app.api.deps import (
    OAuthClientServiceDep,
    OwnedClientDep,
    RequireSessionDep,
    RequireSuperuserDep,
)
from app.schemas.client import (
    ClientCreatedResponseSchema,
    ClientResponseSchema,
    CreateClientSchema,
    RotateSecretResponseSchema,
    UpdateClientSchema,
    VerifyClientSchema,
)

router = APIRouter()


@router.get("/", response_model=list[ClientResponseSchema])
async def get_my_clients(
    client_services: OAuthClientServiceDep,
    current_user: RequireSessionDep,
):
    return await client_services.list_client_by_owner(current_user.id)


@router.get("/all", response_model=list[ClientResponseSchema])
async def get_list_all_clients(
    client_services: OAuthClientServiceDep,
    _: RequireSuperuserDep,
):
    return await client_services.list_active_clients()


@router.get("/{client_id}", response_model=ClientResponseSchema)
async def get_owner_client_information(client: OwnedClientDep):
    return client


@router.post("/", response_model=ClientCreatedResponseSchema)
async def create_client(
    body: CreateClientSchema,
    client_services: OAuthClientServiceDep,
    current_user: RequireSessionDep,
):
    return await client_services.create_client(
        owner_id=current_user.id, **body.model_dump()
    )


@router.patch("/{client_id}", response_model=ClientResponseSchema)
async def update_client_information(
    body: UpdateClientSchema,
    client: OwnedClientDep,
    client_services: OAuthClientServiceDep,
):
    data = body.model_dump(exclude_none=True)
    if not data:
        return client
    return await client_services.update_client(client.client_id, data)


@router.post("/{client_id}/rotate-secret", response_model=RotateSecretResponseSchema)
async def rotate_client_secret(
    client: OwnedClientDep,
    client_services: OAuthClientServiceDep,
):
    new_secret = await client_services.rotate_secret(client.client_id)
    return RotateSecretResponseSchema(client_secret=new_secret)


@router.post("/{client_id}/activate", response_model=ClientResponseSchema)
async def activate_client(
    client: OwnedClientDep,
    client_services: OAuthClientServiceDep,
):
    return await client_services.activate_client(client.client_id)


@router.patch("/{client_id}/verification", response_model=ClientResponseSchema)
async def verify_client(
    client_id: str,
    body: VerifyClientSchema,
    client_services: OAuthClientServiceDep,
    _: RequireSuperuserDep,
):
    return await client_services.update_client(
        client_id, {"is_verified": body.is_verified}
    )


@router.delete("/{client_id}", response_model=ClientResponseSchema)
async def deactivate_client(
    client: OwnedClientDep,
    client_services: OAuthClientServiceDep,
):
    return await client_services.deactivate_client(client.client_id)
