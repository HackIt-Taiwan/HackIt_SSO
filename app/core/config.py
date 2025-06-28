from pydantic_settings import BaseSettings
from pydantic import EmailStr
from typing import Optional, Dict, Any
from fastapi import Request
import json
import logging
import time

class Settings(BaseSettings):
    # Database Service (centralized API)
    DATABASE_SERVICE_URL: str = "http://localhost:8001"
    DATABASE_SERVICE_SECRET: str
    
    # Redis - Use single URL for better compatibility
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    MAGIC_LINK_TOKEN_EXPIRE_MINUTES: int = 15

    # OIDC Configuration
    OIDC_ISSUER: str = "https://sso.hackit.tw"
    OIDC_KEY_ID: str = "hackit-sso-key-1"
    OIDC_ADMIN_KEY: str = ""  # Admin key for OIDC client registration
    OIDC_CLIENTS: str = "W10="  # Base64 encoded JSON array of OIDC clients (default: [] -> W10=)

    # Mail Settings
    MAIL_USERNAME: str = ""
    MAIL_PASSWORD: str = ""
    MAIL_FROM: EmailStr = "noreply@hackit.tw"
    MAIL_PORT: int = 587
    MAIL_SERVER: str = "smtp.gmail.com"
    MAIL_FROM_NAME: str = "HackIt SSO"
    MAIL_STARTTLS: bool = True
    MAIL_SSL_TLS: bool = False
    USE_CREDENTIALS: bool = True
    VALIDATE_CERTS: bool = True
    
    # Cloudflare Turnstile settings
    TURNSTILE_SITE_KEY: str = ""
    TURNSTILE_SECRET_KEY: str = ""

    # SSO Settings
    SSO_DOMAIN: str = "sso.hackit.tw"
    ALLOWED_DOMAINS: str = "hackit.tw,*.hackit.tw"
    
    # Environment
    ENVIRONMENT: str = "production"
    
    # Static Assets Version (for cache busting)
    STATIC_VERSION: str = "20250625_v2"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

# SSO session management
logger = logging.getLogger(__name__)

def get_cookie_domain() -> str:
    """Get the correct cookie domain for SSO sessions."""
    # For hackit.tw domain structure, use .hackit.tw for cross-subdomain cookies
    return ".hackit.tw"

async def check_user_session(request: Request) -> Optional[Dict[str, Any]]:
    """
    Centralized user session checking function.
    Check if user has an active SSO session via cookie.
    """
    try:
        # Check for SSO session cookie
        session_cookie = request.cookies.get("hackit_sso_session")
        if not session_cookie:
            logger.debug("No SSO session cookie found")
            return None
        
        # Get session data from Redis
        from app.core.database import redis_client
        session_data = redis_client.get(f"session:{session_cookie}")
        if not session_data:
            logger.debug(f"No session data found in Redis for cookie: {session_cookie[:8]}...")
            return None
        
        # Parse session data
        session_info = json.loads(session_data)
        
        # Verify session is still valid
        current_time = int(time.time())
        expires_at = session_info.get("expires_at", 0)
        
        if expires_at < current_time:
            # Session expired, clean up
            redis_client.delete(f"session:{session_cookie}")
            logger.info(f"Session expired and cleaned up: {session_cookie[:8]}...")
            return None
        
        logger.debug(f"Valid session found for user: {session_info.get('email')}")
        return session_info
        
    except Exception as e:
        logger.error(f"Error checking user session: {str(e)}")
        return None

def get_avatar_url(user_id: str) -> str:
    """Generate Database API avatar URL for a user."""
    return f"{settings.DATABASE_SERVICE_URL}/users/{user_id}/avatar" 