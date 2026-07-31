import os
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Request, Response, HTTPException

SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "phishguard-enterprise-secure-production-key-2026")
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="phishguard-session-salt")

def create_secure_session_token(session_data: dict) -> str:
    """
    Encrypts and signs session data into a secure token.
    """
    return serializer.dumps(session_data)

def verify_secure_session_token(token: str, max_age: int = 3600) -> dict:
    """
    Verifies and decrypts the session token, enforcing a 1-hour expiration (3600 seconds).
    """
    try:
        data = serializer.loads(token, max_age=max_age)
        return data
    except (SignatureExpired, BadSignature) as e:
        raise HTTPException(status_code=401, detail="Session expired or invalid. Please re-verify via security gate.")
