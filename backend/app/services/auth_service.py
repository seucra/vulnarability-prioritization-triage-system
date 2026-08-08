"""
Authentication & User Management Service Layer
Repository: seucra/vulnarability-prioritization-triage-system
"""

from typing import Dict, List, Optional
from backend.app.core.auth_db import auth_db
from backend.app.core.security import create_access_token, hash_password, verify_password, verify_access_token
from backend.app.schemas.auth import UserRegisterRequest, UserLoginRequest, UserResponse, LoginResponse


class AuthService:
    def register_user(self, req: UserRegisterRequest) -> UserResponse:
        # Prevent privilege escalation during registration
        if req.role not in ["analyst", "researcher"]:
            raise ValueError("Registration permits 'analyst' or 'researcher' roles only")

        existing = auth_db.get_user_by_email(req.email)
        if existing:
            raise ValueError("Email address is already registered")

        pass_hash = hash_password(req.password)
        user_dict = auth_db.create_user(
            email=req.email,
            name=req.name,
            password_hash=pass_hash,
            role=req.role
        )
        return UserResponse(
            id=user_dict["id"],
            email=user_dict["email"],
            name=user_dict["name"],
            role=user_dict["role"],
            created_at=user_dict["created_at"],
            is_active=bool(user_dict["is_active"])
        )

    def login_user(self, req: UserLoginRequest) -> LoginResponse:
        user_dict = auth_db.get_user_by_email(req.email)
        if not user_dict:
            raise ValueError("Invalid credentials or disabled account")

        if not bool(user_dict["is_active"]):
            raise ValueError("Account is currently disabled")

        if not verify_password(req.password, user_dict["password_hash"]):
            raise ValueError("Invalid credentials or disabled account")

        token_payload = {
            "sub": str(user_dict["id"]),
            "email": user_dict["email"],
            "role": user_dict["role"]
        }
        token = create_access_token(token_payload)

        user_resp = UserResponse(
            id=user_dict["id"],
            email=user_dict["email"],
            name=user_dict["name"],
            role=user_dict["role"],
            created_at=user_dict["created_at"],
            is_active=bool(user_dict["is_active"])
        )
        return LoginResponse(access_token=token, token_type="bearer", user=user_resp)

    def get_user_from_token(self, token: str) -> Optional[UserResponse]:
        payload = verify_access_token(token)
        if not payload or "sub" not in payload:
            return None

        try:
            user_id = int(payload["sub"])
            user_dict = auth_db.get_user_by_id(user_id)
            if not user_dict or not bool(user_dict["is_active"]):
                return None

            return UserResponse(
                id=user_dict["id"],
                email=user_dict["email"],
                name=user_dict["name"],
                role=user_dict["role"],
                created_at=user_dict["created_at"],
                is_active=bool(user_dict["is_active"])
            )
        except Exception:
            return None

    def list_users(self) -> List[UserResponse]:
        users = auth_db.list_users()
        return [
            UserResponse(
                id=u["id"],
                email=u["email"],
                name=u["name"],
                role=u["role"],
                created_at=u["created_at"],
                is_active=bool(u["is_active"])
            )
            for u in users
        ]

    def update_user_status(self, user_id: int, is_active: bool) -> UserResponse:
        updated = auth_db.set_user_active_status(user_id, is_active)
        if not updated:
            raise ValueError(f"User with ID {user_id} not found")
        return UserResponse(
            id=updated["id"],
            email=updated["email"],
            name=updated["name"],
            role=updated["role"],
            created_at=updated["created_at"],
            is_active=bool(updated["is_active"])
        )


auth_service = AuthService()
