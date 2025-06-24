import httpx
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

class TurnstileService:
    
    @staticmethod
    async def verify_turnstile_token(token: str, remote_ip: str = None) -> bool:
        """
        Verify Cloudflare Turnstile token.
        
        Args:
            token: The Turnstile token from frontend
            remote_ip: Client IP address (optional)
            
        Returns:
            bool: True if verification successful, False otherwise
        """
        try:
            # Turnstile verification endpoint
            verify_url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
            
            # Prepare verification data
            verify_data = {
                "secret": settings.TURNSTILE_SECRET_KEY,
                "response": token
            }
            
            # Add remote IP if provided
            if remote_ip:
                verify_data["remoteip"] = remote_ip
            
            # Make verification request
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    verify_url,
                    data=verify_data,
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    if result.get("success", False):
                        logger.info("Turnstile verification successful")
                        return True
                    else:
                        error_codes = result.get("error-codes", [])
                        logger.warning(f"Turnstile verification failed: {error_codes}")
                        return False
                else:
                    logger.error(f"Turnstile API returned status {response.status_code}")
                    return False
                    
        except httpx.TimeoutException:
            logger.error("Turnstile verification timeout")
            return False
        except Exception as e:
            logger.error(f"Error verifying Turnstile token: {str(e)}")
            return False 