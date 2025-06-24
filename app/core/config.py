from pydantic_settings import BaseSettings
from pydantic import EmailStr
from typing import Optional

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

    class Config:
        env_file = ".env"

settings = Settings() 