import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.common.enum import MFAMethod
from app.models.base import Base, TimestampMixin, UUIDMixin


class UserMfaMethod(UUIDMixin, TimestampMixin, Base):
    """
    One row per 2FA that a user has turned on.
    """

    __tablename__ = "user_mfa_methods"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    method: Mapped[MFAMethod] = mapped_column(
        Enum(
            MFAMethod,
            native_enum=False,
            create_constraint=False,
            length=20,
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
    )
    secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        UniqueConstraint("user_id", "method", name="uq_user_mfa_methods_user_method"),
    )

    def __repr__(self) -> str:
        return f"<UserMfaMethod user_id={self.user_id} method={self.method}>"
