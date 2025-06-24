from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
from datetime import datetime

class OIDCDiscoveryResponse(BaseModel):
    """OIDC Discovery Document according to RFC 8414"""
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    end_session_endpoint: Optional[str] = None  # OIDC logout endpoint
    scopes_supported: List[str] = ["openid", "profile", "email"]
    response_types_supported: List[str] = ["code", "token", "id_token"]
    response_modes_supported: List[str] = ["query", "fragment", "form_post"]
    grant_types_supported: List[str] = ["authorization_code", "implicit", "refresh_token"]
    subject_types_supported: List[str] = ["public"]
    id_token_signing_alg_values_supported: List[str] = ["RS256", "HS256"]
    token_endpoint_auth_methods_supported: List[str] = ["client_secret_basic", "client_secret_post"]
    claims_supported: List[str] = [
        "sub", "name", "given_name", "family_name", "email", "email_verified",
        "locale", "picture", "preferred_username", "iss", "aud", "exp", "iat"
    ]

class OIDCAuthorizationRequest(BaseModel):
    """OIDC Authorization Request"""
    response_type: str
    client_id: str
    redirect_uri: str
    scope: str = "openid"
    state: Optional[str] = None
    nonce: Optional[str] = None
    prompt: Optional[str] = None
    max_age: Optional[int] = None
    ui_locales: Optional[str] = None

class OIDCTokenRequest(BaseModel):
    """OIDC Token Request"""
    grant_type: str
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    refresh_token: Optional[str] = None

class OIDCTokenResponse(BaseModel):
    """OIDC Token Response"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    id_token: str
    refresh_token: Optional[str] = None
    scope: str

class OIDCUserInfo(BaseModel):
    """OIDC UserInfo Response"""
    sub: str
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    picture: Optional[str] = None
    preferred_username: Optional[str] = None
    locale: Optional[str] = None
    updated_at: Optional[int] = None

class OIDCClient(BaseModel):
    """OIDC Client Registration"""
    client_id: str
    client_secret: str
    client_name: str
    redirect_uris: List[str]
    grant_types: List[str] = ["authorization_code"]
    response_types: List[str] = ["code"]
    scope: str = "openid profile email"
    token_endpoint_auth_method: str = "client_secret_basic"
    
class JWKSet(BaseModel):
    """JSON Web Key Set"""
    keys: List[Dict[str, Any]]

class IDTokenClaims(BaseModel):
    """ID Token Claims"""
    iss: str  # Issuer
    sub: str  # Subject
    aud: str  # Audience (client_id)
    exp: int  # Expiration time
    iat: int  # Issued at
    nonce: Optional[str] = None
    auth_time: Optional[int] = None
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    picture: Optional[str] = None
    preferred_username: Optional[str] = None 