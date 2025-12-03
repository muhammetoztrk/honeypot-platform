from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import bcrypt

from .config import settings
from .database import get_db
from . import models

# Use bcrypt directly to avoid passlib compatibility issues
try:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
except Exception:
    # Fallback to direct bcrypt if passlib fails
    pwd_context = None
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24


def hash_password(password: str) -> str:
    # Truncate password to 72 bytes to avoid bcrypt limitation
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    
    if pwd_context:
        try:
            return pwd_context.hash(password_bytes.decode('utf-8', errors='ignore'))
        except Exception:
            pass
    
    # Fallback to direct bcrypt
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt).decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    
    if pwd_context:
        try:
            return pwd_context.verify(password_bytes.decode('utf-8', errors='ignore'), password_hash)
        except Exception:
            pass
    
    # Fallback to direct bcrypt
    try:
        return bcrypt.checkpw(password_bytes, password_hash.encode('utf-8'))
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=ALGORITHM)


def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> models.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
        user_id: int = int(payload.get("sub"))
    except JWTError:
        raise credentials_exception

    user = db.get(models.User, user_id)
    if not user:
        raise credentials_exception
    return user



