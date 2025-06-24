import secrets
import uuid
from typing import Optional
from app.core.database import redis_client
from app.core.config import settings
from app.services.email_service import send_magic_link_email
from app.auth.jwt_handler import create_access_token, extract_email_from_magic_token
from app.crud.user_api import update_user_login_info, get_user_by_email, get_user_by_id
import logging

logger = logging.getLogger(__name__)

class MagicLinkService:
    
    @staticmethod
    def generate_magic_token() -> str:
        """Generate a secure random token for magic link."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    async def send_magic_link(email: str, base_url: str = "http://localhost:8000", client_ip: str = None, oidc_params: dict = None) -> dict:
        """Generate and send magic link to user's email."""
        try:
            # First check if user exists in database service
            user = await get_user_by_email(email)
            if not user:
                logger.warning(f"User with email {email} not found in database")
                return {
                    "success": False,
                    "message": "查無此帳號，請確認您的電子郵件地址是否正確。"
                }
            
            # Check for existing valid magic link and rate limiting
            email_hash = email.replace("@", "_at_").replace(".", "_dot_")  # Safe key format
            existing_token_key = f"magic_link_email:{email_hash}"
            rate_limit_key = f"magic_link_count:{email_hash}"
            
            # Check if there's already a valid token for this email
            existing_token = redis_client.get(existing_token_key)
            send_count = int(redis_client.get(rate_limit_key) or 0)
            
            if existing_token:
                # Check send count for rate limiting
                if send_count >= 3:
                    logger.warning(f"Rate limit exceeded for email {email}")
                    return {
                        "success": False,
                        "message": "您發送請求太頻繁了！請稍後再試。"
                    }
                
                # Increment send count and extend TTL
                redis_client.incr(rate_limit_key)
                redis_client.expire(rate_limit_key, settings.MAGIC_LINK_TOKEN_EXPIRE_MINUTES * 60)
                
                # Reuse existing token
                magic_token = existing_token
                logger.info(f"Reusing existing magic token for {email} (send count: {send_count + 1})")
            else:
                # Generate new token
                magic_token = MagicLinkService.generate_magic_token()
                
                # Store token mapping with TTL (15 minutes)
                redis_client.set(
                    existing_token_key, 
                    magic_token, 
                    ex=settings.MAGIC_LINK_TOKEN_EXPIRE_MINUTES * 60
                )
                
                # Initialize send count
                redis_client.set(
                    rate_limit_key, 
                    1, 
                    ex=settings.MAGIC_LINK_TOKEN_EXPIRE_MINUTES * 60
                )
                
                logger.info(f"Generated new magic token for {email}")
            
            # Store the magic token in Redis with email, timestamp, and OIDC params
            magic_link_data = {
                "email": email,
                "timestamp": str(uuid.uuid4()),  # Unique identifier for this link
                "ip": client_ip,
                "oidc_params": oidc_params  # Store OIDC parameters for callback
            }
            
            # Store magic link data as JSON string for OIDC support
            import json
            redis_client.set(
                f"magic_link:{magic_token}", 
                json.dumps(magic_link_data), 
                ex=settings.MAGIC_LINK_TOKEN_EXPIRE_MINUTES * 60  # 15 minutes TTL
            )
            
            # Generate magic link URL
            magic_link_url = f"{base_url}/auth/verify?token={magic_token}"
            
            # Send email with magic link and IP info
            await send_magic_link_email(
                email, 
                magic_link_url, 
                user.get('real_name', 'User'),
                client_ip
            )
            
            return {
                "success": True,
                "message": "Magic link 已發送到您的信箱，請檢查您的郵件（包含垃圾信件夾）。"
            }
                
        except Exception as e:
            logger.error(f"Error sending magic link to {email}: {str(e)}")
            return {
                "success": False,
                "message": "系統錯誤，請稍後再試。"
            }
    
    @staticmethod
    def verify_magic_token(token: str) -> Optional[dict]:
        """Verify magic token and return token data if valid."""
        try:
            # Get token data from Redis
            token_data = redis_client.get(f"magic_link:{token}")
            if not token_data:
                logger.warning(f"Magic token not found or expired: {token}")
                return None
            
            # Try to parse as JSON first (new format), fallback to old format
            try:
                import json
                data = json.loads(token_data)
                logger.info(f"Magic token verified for {data.get('email')}")
                return data
            except (json.JSONDecodeError, TypeError):
                # Legacy format: email|timestamp|ip
                parts = token_data.split('|')
                if len(parts) >= 1:
                    email = parts[0]
                    logger.info(f"Magic token verified for {email} (legacy format)")
                    return {"email": email, "oidc_params": None}
                else:
                    logger.error(f"Invalid token data format: {token_data}")
                    return None
                
        except Exception as e:
            logger.error(f"Error verifying magic token {token}: {str(e)}")
            return None
    
    @staticmethod
    async def create_user_session(email: str) -> Optional[dict]:
        """Create user session and return access token."""
        try:
            # Get existing user only (no creation)
            user = await get_user_by_email(email)
            if not user:
                logger.error(f"User not found for {email}")
                return None
            
            # Update login info using database API
            await update_user_login_info(user['id'], "magic_link")
            
            # Create access token with complete user info
            token_data = {
                "sub": user['id'],
                "email": user['email'],
                "real_name": user['real_name'],
                "user_id": user['user_id'],
                "guild_id": user['guild_id'],
                "avatar_base64": user.get('avatar_base64')
            }
            access_token = create_access_token(token_data)
            
            # Return session info
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "user_info": {
                    "id": user['id'],
                    "email": user['email'],
                    "real_name": user['real_name'],
                    "user_id": user['user_id'],
                    "guild_id": user['guild_id'],
                    "avatar_base64": user.get('avatar_base64'),
                    "source": user.get('source'),
                    "education_stage": user.get('education_stage'),
                    "registered_at": user.get('registered_at')
                }
            }
            
        except Exception as e:
            logger.error(f"Error creating user session for {email}: {str(e)}")
            return None 