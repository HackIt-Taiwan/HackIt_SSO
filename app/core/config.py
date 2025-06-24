from pydantic_settings import BaseSettings
from pydantic import EmailStr

class Settings(BaseSettings):
    # Database
    MONGODB_URI: str
    MONGODB_DATABASE: str
    
    # Database Service (new centralized service)
    DATABASE_SERVICE_URL: str = "http://localhost:8001"
    DATABASE_SERVICE_SECRET: str
    
    # Redis
    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_PASSWORD: str
    REDIS_DB: int

    # JWT
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    MAGIC_LINK_TOKEN_EXPIRE_MINUTES: int

    # OIDC Configuration
    OIDC_ISSUER: str = "https://sso.hackit.tw"
    OIDC_KEY_ID: str = "hackit-sso-key-1"

    # Mail Settings
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: EmailStr
    MAIL_PORT: int
    MAIL_SERVER: str
    MAIL_STARTTLS: bool
    MAIL_SSL_TLS: bool
    USE_CREDENTIALS: bool
    VALIDATE_CERTS: bool
    
    # Cloudflare Turnstile settings
    TURNSTILE_SITE_KEY: str
    TURNSTILE_SECRET_KEY: str


    class Config:
        env_file = ".env"

settings = Settings() 