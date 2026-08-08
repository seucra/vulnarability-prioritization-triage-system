"""
Authentication & Role Administration REST API Endpoints
Repository: seucra/vulnarability-prioritization-triage-system
"""

from typing import List
from fastapi import APIRouter, Depends, status, HTTPException
from backend.app.api.deps import get_current_user, require_roles
from backend.app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    LoginResponse,
    UserStatusUpdateRequest
)
from backend.app.services.auth_service import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register Demonstration Account",
    description="Registers a new demonstration user with Security Analyst or Researcher role. Administrator self-registration is strictly prohibited."
)
def register_user(req: UserRegisterRequest):
    try:
        return auth_service.register_user(req)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate User & Issue Token",
    description="Validates credentials against local account store and issues an HMAC-SHA256 signed access token."
)
def login_user(req: UserLoginRequest):
    try:
        return auth_service.login_user(req)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Authenticated User Context",
    description="Returns metadata and active role for the currently authenticated bearer token."
)
def get_authenticated_user_context(current_user: UserResponse = Depends(get_current_user)):
    return current_user


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout User Session",
    description="Invalidates user session token context."
)
def logout_user(current_user: UserResponse = Depends(get_current_user)):
    return {"status": "success", "message": "Successfully logged out user session"}


@router.get(
    "/users",
    response_model=List[UserResponse],
    status_code=status.HTTP_200_OK,
    summary="List User Accounts (Admin Only)",
    description="Lists all user accounts in the local database. Strictly restricted to Administrator role."
)
def list_user_accounts(current_user: UserResponse = Depends(require_roles(["admin"]))):
    return auth_service.list_users()


@router.patch(
    "/users/{user_id}/status",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update Account Status (Admin Only)",
    description="Enables or disables a user account. Strictly restricted to Administrator role."
)
def update_user_account_status(
    user_id: int,
    req: UserStatusUpdateRequest,
    current_user: UserResponse = Depends(require_roles(["admin"]))
):
    try:
        return auth_service.update_user_status(user_id, req.is_active)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
