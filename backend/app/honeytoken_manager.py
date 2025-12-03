"""Honeytoken Management"""
from sqlalchemy.orm import Session
from datetime import datetime
from . import models
import secrets


def create_honeytoken(name: str, token_type: str, db: Session) -> models.Honeytoken:
    """Create a new honeytoken"""
    # Generate token value based on type
    if token_type == "credential":
        token_value = f"admin:{secrets.token_hex(16)}"
    elif token_type == "api_key":
        token_value = secrets.token_urlsafe(32)
    elif token_type == "file":
        token_value = f"secret_{secrets.token_hex(8)}.txt"
    elif token_type == "url":
        token_value = f"https://example.com/api/{secrets.token_hex(16)}"
    else:
        token_value = secrets.token_urlsafe(32)
    
    token = models.Honeytoken(
        name=name,
        token_type=token_type,
        token_value=token_value,
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    return token


def check_honeytoken_trigger(value: str, db: Session) -> dict:
    """Check if a value matches any honeytoken"""
    tokens = db.query(models.Honeytoken).filter_by(status="active").all()
    
    for token in tokens:
        if token.token_value in value or value in token.token_value:
            # Trigger honeytoken
            token.status = "triggered"
            token.triggered_at = datetime.utcnow()
            db.commit()
            
            return {
                "triggered": True,
                "token_id": token.id,
                "token_name": token.name,
                "token_type": token.token_type,
                "severity": "high",
            }
    
    return {"triggered": False}

