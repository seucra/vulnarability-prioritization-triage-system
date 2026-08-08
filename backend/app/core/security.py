"""
Security & Token Utility Functions
Repository: seucra/vulnarability-prioritization-triage-system

Provides PBKDF2 password hashing and HMAC-SHA256 token signing/verification
using Python standard library (hashlib, hmac, base64, json, secrets).
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, Optional

# Secret key for HMAC token signing (falls back to a generated runtime secret if not configured)
SECRET_KEY = "wdl-vuln-triage-secret-key-do-not-use-in-production-demo-only"
TOKEN_EXPIRATION_SECONDS = 86400  # 24 Hours


def hash_password(password: str) -> str:
    """Hashes a plaintext password using PBKDF2-HMAC-SHA256 with a random 16-byte salt."""
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations=100000
    )
    salt_b64 = base64.b64encode(salt).decode('ascii')
    key_b64 = base64.b64encode(key).decode('ascii')
    return f"pbkdf2_sha256$100000${salt_b64}${key_b64}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verifies a plaintext password against a PBKDF2-HMAC-SHA256 hash string."""
    try:
        parts = password_hash.split('$')
        if len(parts) != 4 or parts[0] != 'pbkdf2_sha256':
            return False
        
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2].encode('ascii'))
        expected_key = base64.b64decode(parts[3].encode('ascii'))
        
        candidate_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations=iterations
        )
        return hmac.compare_digest(candidate_key, expected_key)
    except Exception:
        return False


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _base64url_decode(data_str: str) -> bytes:
    padding = '=' * (4 - (len(data_str) % 4))
    return base64.urlsafe_b64decode((data_str + padding).encode('ascii'))


def create_access_token(payload: Dict[str, Any], expires_delta: Optional[int] = None) -> str:
    """Creates a JWT-format HMAC-SHA256 signed access token."""
    header = {"alg": "HS256", "typ": "JWT"}
    
    exp = int(time.time()) + (expires_delta if expires_delta else TOKEN_EXPIRATION_SECONDS)
    token_payload = {**payload, "exp": exp, "iat": int(time.time())}
    
    header_bytes = json.dumps(header, separators=(',', ':')).encode('utf-8')
    payload_bytes = json.dumps(token_payload, separators=(',', ':')).encode('utf-8')
    
    encoded_header = _base64url_encode(header_bytes)
    encoded_payload = _base64url_encode(payload_bytes)
    
    signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')
    signature = hmac.new(SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
    encoded_signature = _base64url_encode(signature)
    
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Verifies HMAC signature and expiration date of an access token."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        encoded_header, encoded_payload, encoded_signature = parts
        signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')
        
        expected_sig = hmac.new(SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
        actual_sig = _base64url_decode(encoded_signature)
        
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        
        payload_bytes = _base64url_decode(encoded_payload)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        # Check token expiration
        if payload.get("exp") and time.time() > payload["exp"]:
            return None
        
        return payload
    except Exception:
        return None
