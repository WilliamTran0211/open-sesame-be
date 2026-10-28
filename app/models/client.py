import uuid
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import ARRAY, Boolean, Enum, ForeignKey, Integer, String, Text, false
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.common.enum import ClientType
from app.models.authorization_code import AuthorizationCode
from app.models.base import Base, TimestampMixin, UUIDMixin
from app.models.oauth_consent import OAuthConsent
from app.models.refresh_token import RefreshToken

if TYPE_CHECKING:
    from app.models.user import User


class OAuthClient(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "oauth_clients"

    # Client identity
    client_id: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
        index=True,
    )
    client_secret_hash: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    client_type: Mapped[ClientType] = mapped_column(
        Enum(ClientType, name="client_type_enum"),
        nullable=False,
        default=ClientType.CONFIDENTIAL,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # OAuth configuration
    redirect_uris: Mapped[List[str]] = mapped_column(ARRAY(String), nullable=False)
    grant_types: Mapped[List[str]] = mapped_column(
        ARRAY(String),
        nullable=False,
        default=lambda: ["authorization_code", "refresh_token"],
    )
    allowed_scopes: Mapped[List[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    require_pkce: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Token TTL overrides in seconds
    access_token_ttl: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    refresh_token_ttl: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false(), nullable=False
    )
    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    owner: Mapped[Optional["User"]] = relationship(
        "User", back_populates="owned_clients"
    )
    authorization_codes: Mapped[List["AuthorizationCode"]] = relationship(
        "AuthorizationCode",
        back_populates="client",
        cascade="all, delete-orphan",
    )
    refresh_tokens: Mapped[List["RefreshToken"]] = relationship(
        "RefreshToken",
        back_populates="client",
        cascade="all, delete-orphan",
    )
    consents: Mapped[List["OAuthConsent"]] = relationship(
        "OAuthConsent",
        back_populates="client",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<OAuthClient id={self.id} name={self.name!r} type={self.client_type}>"
