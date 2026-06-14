"""
auth.py — JWT authentication helpers
- Password hashing with bcrypt
- JWT token creation/validation
- Fernet encryption for stored device passwords
"""

import os
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User

# ─────────────────────────────────────────────
# Config (loaded from environment)
# ─────────────────────────────────────────────

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production-use-openssl-rand-hex-32")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))  # 8 hours

# Fernet key for encrypting device passwords in DB
# Generate once: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
FERNET_KEY = os.getenv("FERNET_KEY", "")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


# ─────────────────────────────────────────────
# Password Hashing
# ─────────────────────────────────────────────

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ─────────────────────────────────────────────
# JWT Tokens
# ─────────────────────────────────────────────

def create_access_token(user_id: int, email: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "email": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency — validates JWT and returns the current User."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: Optional[str] = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


# ─────────────────────────────────────────────
# Device Password Encryption
# ─────────────────────────────────────────────

def _get_fernet() -> Fernet:
    if not FERNET_KEY:
        raise RuntimeError(
            "FERNET_KEY not set in environment. "
            "Generate one: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(FERNET_KEY.encode())


def encrypt_password(plain_password: str) -> str:
    """Encrypt a device password for safe storage in DB."""
    f = _get_fernet()
    return f.encrypt(plain_password.encode()).decode()


def decrypt_password(encrypted_password: str) -> str:
    """Decrypt a stored device password for SSH use."""
    f = _get_fernet()
    return f.decrypt(encrypted_password.encode()).decode()
