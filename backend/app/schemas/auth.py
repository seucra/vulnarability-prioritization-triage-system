"""
Authentication & Authorization Pydantic Schemas
Repository: seucra/vulnarability-prioritization-triage-system
"""

import re
from typing import Literal
from pydantic import BaseModel, Field, field_validator

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class UserRegisterRequest(BaseModel):
    email: str = Field(..., description="Valid email address")
    password: str = Field(..., min_length=8, description="Password (minimum 8 characters)")
    name: str = Field(..., min_length=2, description="User full name")
    role: Literal["analyst", "researcher"] = Field(..., description="Desired user role (analyst or researcher only)")

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        v_stripped = v.strip().lower()
        if not EMAIL_REGEX.match(v_stripped):
            raise ValueError("Invalid email format")
        return v_stripped

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


class UserLoginRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password")


class UserResponse(BaseModel):
    id: int = Field(..., description="User unique ID")
    email: str = Field(..., description="User email address")
    name: str = Field(..., description="User full name")
    role: str = Field(..., description="User role ('analyst', 'researcher', 'admin')")
    created_at: str = Field(..., description="Account creation timestamp")
    is_active: bool = Field(..., description="Account active status")


class LoginResponse(BaseModel):
    access_token: str = Field(..., description="HMAC-SHA256 signed access token")
    token_type: str = Field("bearer", description="Token type")
    user: UserResponse = Field(..., description="Authenticated user metadata")


class UserStatusUpdateRequest(BaseModel):
    is_active: bool = Field(..., description="New account active status")
