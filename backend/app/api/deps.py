"""
FastAPI Authentication & RBAC Authorization Dependencies
Repository: seucra/vulnarability-prioritization-triage-system
"""

from typing import List
from fastapi import Depends, HTTPException, Header, status
from backend.app.schemas.auth import UserResponse
from backend.app.services.auth_service import auth_service


def get_current_user(authorization: str = Header(None, alias="Authorization")) -> UserResponse:
    """FastAPI dependency to extract and verify the current authenticated user."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token missing",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = authorization
    if authorization.startswith("Bearer "):
        token = authorization[7:].strip()

    user = auth_service.get_user_from_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or disabled authentication token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return user


def require_roles(allowed_roles: List[str]):
    """Returns a dependency function that enforces server-side role-based authorization."""
    def role_checker(current_user: UserResponse = Depends(get_current_user)) -> UserResponse:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Access requires one of the following roles: {', '.join(allowed_roles)}"
            )
        return current_user
    return role_checker
