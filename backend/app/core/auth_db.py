"""
SQLite User Account Database Persistence Engine
Repository: seucra/vulnarability-prioritization-triage-system

Manages user persistence in a lightweight local SQLite database (data/auth_users.sqlite).
Pre-seeds a default demonstration Administrator account.
"""

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
from backend.app.config import settings
from backend.app.core.security import hash_password

DB_PATH = settings.REPO_ROOT / "data" / "auth_users.sqlite"


class AuthDatabase:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes tables and seeds default demo Administrator account."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1
                );
            """)
            conn.commit()
            
            # Seed default demo Administrator if no users exist or admin missing
            cursor.execute("SELECT id FROM users WHERE role = 'admin'")
            admin_row = cursor.fetchone()
            if not admin_row:
                admin_email = "admin@vuln-triage.sec"
                admin_pass_hash = hash_password("AdminDemoPassword123!")
                now_iso = datetime.now(timezone.utc).isoformat()
                cursor.execute("""
                    INSERT INTO users (email, name, password_hash, role, created_at, is_active)
                    VALUES (?, ?, ?, ?, ?, 1)
                """, (admin_email, "Demonstration Administrator", admin_pass_hash, "admin", now_iso))
                conn.commit()

    def create_user(self, email: str, name: str, password_hash: str, role: str) -> Dict[str, Any]:
        """Creates a new user record."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO users (email, name, password_hash, role, created_at, is_active)
                    VALUES (?, ?, ?, ?, ?, 1)
                """, (email.lower(), name, password_hash, role, now_iso))
                conn.commit()
                user_id = cursor.lastrowid
                return self.get_user_by_id(user_id)
            except sqlite3.IntegrityError:
                raise ValueError("Email address is already registered")

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_users(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, name, role, created_at, is_active FROM users ORDER BY id ASC")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def set_user_active_status(self, user_id: int, is_active: bool) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Prevent disabling primary admin (id=1 or role='admin')
            cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if row and row["role"] == "admin" and not is_active:
                raise ValueError("Cannot disable the primary demonstration Administrator account")

            cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if is_active else 0, user_id))
            conn.commit()
            return self.get_user_by_id(user_id)


auth_db = AuthDatabase()
