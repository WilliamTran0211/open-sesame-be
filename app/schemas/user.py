import re
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


class UserSchemaBase(BaseModel):
    email: str | None = None
    full_name: str | None = None


class UserResponseSchema(BaseModel):
    id: uuid.UUID
    email: EmailStr
    full_name: Optional[str]
    is_active: bool
    is_verified: bool
    is_superuser: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserInfoResponseSchema(BaseModel):
    """User info filtered by token scope."""

    sub: uuid.UUID
    email: Optional[EmailStr] = None
    email_verified: Optional[bool] = None
    name: Optional[str] = None


class UserLogin(BaseModel):
    email: EmailStr = Field(..., description="Email for login")
    password: str = Field(..., description="Password for login")


class CreateUserSchema(BaseModel):
    email: EmailStr = Field(
        ..., description="Valid email address", examples=["user@company.com"]
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=100,
        description="Password must be 8-100 characters",
    )
    full_name: Optional[str] = Field(default=None, max_length=255)

    @field_validator("password")
    def validate_password_complexity(cls, v):
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one number")
        return v


class UpdateUserSchema(BaseModel):
    email: Optional[EmailStr] = Field(default=None, description="New email")
    full_name: Optional[str] = Field(default=None, max_length=255)


class ChangePasswordSchema(BaseModel):
    current_password: str = Field(
        ...,
        min_length=8,
        max_length=100,
        description="Password must be 8-100 characters",
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=100,
        description="Password must be 8-100 characters",
    )

    @field_validator("new_password")
    def validate_password_complexity(cls, v):
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one number")
        return v
