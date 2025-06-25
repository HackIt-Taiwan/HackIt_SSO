from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any

class OIDCParams(BaseModel):
    """OIDC parameters for authorization flow"""
    client_id: Optional[str] = None
    redirect_uri: Optional[str] = None
    scope: Optional[str] = None
    state: Optional[str] = None
    nonce: Optional[str] = None

class MagicLinkRequest(BaseModel):
    email: EmailStr
    turnstile_token: str
    oidc_state_id: Optional[str] = None

class MagicLinkResponse(BaseModel):
    message: str
    success: bool

class TokenVerifyRequest(BaseModel):
    token: str

class TokenVerifyResponse(BaseModel):
    message: str
    success: bool
    access_token: Optional[str] = None
    token_type: Optional[str] = "bearer"
    user_info: Optional[dict] = None

class UserResponse(BaseModel):
    user_id: int
    email: str
    real_name: str
    guild_id: int
    source: Optional[str] = None
    education_stage: Optional[str] = None
    registered_at: str 