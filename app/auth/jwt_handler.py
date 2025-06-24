from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from app.core.config import settings

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_magic_link_token(email: str) -> str:
    """Create JWT token for magic link."""
    expire = datetime.utcnow() + timedelta(minutes=settings.MAGIC_LINK_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "email": email,
        "exp": expire,
        "type": "magic_link",
        "iat": datetime.utcnow()
    }
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_token(token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
    """Verify JWT token and return payload."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        
        # Check token type
        if payload.get("type") != token_type:
            return None
            
        # Check expiration
        exp = payload.get("exp")
        if exp is None or datetime.utcnow() > datetime.fromtimestamp(exp):
            return None
            
        return payload
    except JWTError:
        return None

def extract_email_from_magic_token(token: str) -> Optional[str]:
    """Extract email from magic link token."""
    payload = verify_token(token, "magic_link")
    if payload:
        return payload.get("email")
    return None 

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and verify access token."""
    return verify_token(token, "access") 