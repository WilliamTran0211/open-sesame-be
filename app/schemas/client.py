from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.common.enum import ClientType


class ClientBaseSchema(BaseModel):
    name: str = Field(..., max_length=255, description="OAuth client name")
    redirect_uris: List[str] = Field(..., description="Allowed redirect URIs")
    grant_types: List[str] = Field(
        default=["authorization_code", "refresh_token"],
        description="Grant types this client is allowed to use",
    )
    allowed_scopes: List[str] = Field(
        default_factory=list,
        description="Scopes this client may request (must already exist in /scopes)",
    )
    client_type: ClientType = Field(
        default=ClientType.CONFIDENTIAL, description="confidential or public"
    )
    require_pkce: bool = Field(
        default=True, description="Require PKCE (mandatory for public clients)"
    )
    access_token_ttl: Optional[int] = Field(
        default=None, description="Override access token TTL, in seconds"
    )
    refresh_token_ttl: Optional[int] = Field(
        default=None, description="Override refresh token TTL, in seconds"
    )


class CreateClientSchema(ClientBaseSchema):
    pass


class UpdateClientSchema(BaseModel):
    name: Optional[str] = Field(default=None, max_length=255)
    redirect_uris: Optional[List[str]] = None
    grant_types: Optional[List[str]] = None
    allowed_scopes: Optional[List[str]] = None
    client_type: Optional[ClientType] = None
    require_pkce: Optional[bool] = None
    access_token_ttl: Optional[int] = None
    refresh_token_ttl: Optional[int] = None


class ClientResponseSchema(BaseModel):
    id: UUID
    client_id: str
    name: str
    client_type: ClientType
    redirect_uris: List[str]
    grant_types: List[str]
    allowed_scopes: List[str]
    require_pkce: bool
    access_token_ttl: Optional[int]
    refresh_token_ttl: Optional[int]
    is_active: bool
    owner_id: Optional[UUID]
    created_at: datetime
    is_verified: bool

    model_config = {"from_attributes": True}


class ClientCreatedResponseSchema(ClientResponseSchema):
    client_secret: Optional[str] = Field(
        default=None,
        description="Plaintext client secret — shown only once, at creation time.",
    )


class RotateSecretResponseSchema(BaseModel):
    client_secret: str = Field(
        description="New plaintext client secret — shown only once."
    )


class ClientPublicInfoSchema(BaseModel):
    client_id: str
    name: str
    allowed_scopes: List[str]
    is_verified: bool
    redirect_uri_registered: Optional[bool] = None


class VerifyClientSchema(BaseModel):
    is_verified: bool
