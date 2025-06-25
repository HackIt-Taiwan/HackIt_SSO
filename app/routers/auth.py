from fastapi import APIRouter, Body, HTTPException, status, Request, Query, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import EmailStr, BaseModel
import jwt
import hashlib
import hmac
import time
import json
from typing import Optional
import secrets

from app.schemas.auth import MagicLinkRequest, MagicLinkResponse, TokenVerifyResponse
from app.services.magic_link_service import MagicLinkService
from app.services.turnstile_service import TurnstileService
from app.core.config import settings
from app.core.database import redis_client
import logging

logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
security = HTTPBearer(auto_error=False)

# SSO API Models
class SSOTokenRequest(BaseModel):
    token: str
    domain: str
    timestamp: Optional[int] = None
    signature: Optional[str] = None

class SSOUserInfo(BaseModel):
    user_id: str
    email: str
    real_name: str
    guild_id: int
    avatar_base64: Optional[str] = None
    education_stage: Optional[str] = None
    source: Optional[str] = None

class SSOResponse(BaseModel):
    success: bool
    user: Optional[SSOUserInfo] = None
    message: str
    expires_at: Optional[int] = None

# Domain validation for HackIt subdomains
ALLOWED_DOMAINS = [
    "hackit.tw",
    "*.hackit.tw",
    "localhost",
    "127.0.0.1"
]

def validate_domain(domain: str) -> bool:
    """Validate if domain is allowed for SSO integration."""
    # Production domains
    if domain in ["hackit.tw", "sso.hackit.tw"]:
        return True
    if domain.endswith(".hackit.tw"):
        return True
    
    # Local development domains
    if domain in ["localhost", "127.0.0.1"]:
        return True
    
    # Support localhost with different ports for testing
    if domain.startswith("localhost:") or domain.startswith("127.0.0.1:"):
        return True
    
    return False

def create_sso_signature(data: str, timestamp: int, domain: str) -> str:
    """Create HMAC signature for SSO request validation."""
    message = f"{data}:{timestamp}:{domain}"
    signature = hmac.new(
        settings.SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature

def verify_sso_signature(data: str, timestamp: int, domain: str, signature: str) -> bool:
    """Verify HMAC signature for SSO request."""
    expected_signature = create_sso_signature(data, timestamp, domain)
    return hmac.compare_digest(expected_signature, signature)

async def create_sso_session(user_info: dict) -> str:
    """Create SSO session and return session ID."""
    try:
        # Generate session ID
        session_id = secrets.token_urlsafe(32)
        
        # Prepare session data
        session_data = {
            "user_id": user_info["id"],
            "email": user_info["email"],
            "real_name": user_info["real_name"],
            "user_id_field": user_info["user_id"],
            "guild_id": user_info["guild_id"],
            "avatar_base64": user_info.get("avatar_base64"),
            "created_at": int(time.time()),
            "expires_at": int(time.time()) + (settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
        }
        
        # Store session in Redis
        redis_client.set(
            f"session:{session_id}",
            json.dumps(session_data),
            ex=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
        logger.info(f"Created SSO session for user {user_info['email']}")
        return session_id
        
    except Exception as e:
        logger.error(f"Error creating SSO session: {str(e)}")
        raise

def get_current_user_from_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Extract user info from JWT token if present."""
    if not credentials:
        return None
    
    try:
        token = credentials.credentials
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

@router.get("/status")
async def check_auth_status(request: Request, current_user = Depends(get_current_user_from_token)):
    """Check if user is authenticated and return user info."""
    if current_user:
        return {
            "authenticated": True,
            "user": {
                "id": current_user.get("sub"),
                "email": current_user.get("email"),
                "real_name": current_user.get("real_name"),
                "user_id": current_user.get("user_id"),
                "guild_id": current_user.get("guild_id"),
                "avatar_base64": current_user.get("avatar_base64")
            }
        }
    else:
        return {"authenticated": False}

@router.post("/logout")
async def logout(request: Request):
    """Logout endpoint (clear session and tokens)."""
    try:
        # Get session cookie
        session_cookie = request.cookies.get("hackit_sso_session")
        if session_cookie:
            # Remove session from Redis
            redis_client.delete(f"session:{session_cookie}")
            logger.info("SSO session cleared on logout")
        
        response = JSONResponse({
            "success": True,
            "message": "登出成功"
        })
        
        # Clear session cookie
        response.delete_cookie(
            key="hackit_sso_session",
            domain=".hackit.tw"
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        return {
            "success": True,  # Still return success for user experience
            "message": "登出成功"
        }

async def check_user_session(request: Request) -> Optional[Dict[str, Any]]:
    """Check if user has an active SSO session via cookie."""
    try:
        # Check for SSO session cookie
        session_cookie = request.cookies.get("hackit_sso_session")
        if not session_cookie:
            return None
        
        # Get session data from Redis
        session_data = redis_client.get(f"session:{session_cookie}")
        if not session_data:
            return None
        
        # Parse session data
        session_info = json.loads(session_data)
        
        # Verify session is still valid
        import time
        if session_info.get("expires_at", 0) < time.time():
            # Session expired, clean up
            redis_client.delete(f"session:{session_cookie}")
            return None
        
        return session_info
        
    except Exception as e:
        logger.error(f"Error checking user session: {str(e)}")
        return None

@router.get("/", response_class=HTMLResponse)
async def login_page(
    request: Request,
    oidc_state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    logout: Optional[str] = Query(None)
):
    """
    Serve the login page with Turnstile configuration and OIDC support.
    Also handles authenticated users by showing them their status.
    """
    
    # Check if user is already authenticated
    user_session = await check_user_session(request)
    if user_session and not logout:
        # User is already logged in, show authenticated state
        logger.info(f"User {user_session.get('email')} already authenticated, showing dashboard")
        
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "authenticated": True,
                "user_info": user_session,
                "static_version": settings.STATIC_VERSION,
                "logout_success": logout == "success"
            }
        )
    
    logger.info(f"Serving login page with Turnstile site key: {settings.TURNSTILE_SITE_KEY}")
    
    # Prepare OIDC parameters for the template
    oidc_params = None
    oidc_client_name = None
    
    # Load OIDC state from Redis if provided
    if oidc_state:
        try:
            oidc_state_data = redis_client.get(f"oidc_pending:{oidc_state}")
            if oidc_state_data:
                oidc_state_info = json.loads(oidc_state_data)
                oidc_params = oidc_state_info
                
                # Get client name for better UX
                from app.services.oidc_service import OIDCService
                oidc_service = OIDCService()
                client = oidc_service.get_client(oidc_state_info["client_id"])
                if client:
                    oidc_client_name = client.client_name
                
                logger.info(f"OIDC login flow initiated for client: {oidc_state_info['client_id']}")
            else:
                logger.warning(f"OIDC state {oidc_state} not found in Redis")
        except Exception as e:
            logger.error(f"Error loading OIDC state: {str(e)}")
            oidc_params = None
    
    # Prepare error message if present
    error_message = None
    if error:
        error_messages = {
            "invalid_token": "此登入連結已過期或無效。請重新請求新的登入連結。",
            "session_failed": "無法建立用戶會話，請稍後再試。",
            "system_error": "系統發生錯誤，請稍後再試。"
        }
        error_message = error_messages.get(error, "發生未知錯誤，請稍後再試。")

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "authenticated": False,
            "turnstile_site_key": settings.TURNSTILE_SITE_KEY,
            "oidc_params": oidc_params,
            "oidc_client_name": oidc_client_name,
            "oidc_state_id": oidc_state,
            "error_message": error_message,
            "static_version": settings.STATIC_VERSION,
            "logout_success": logout == "success"
        }
    )

@router.post("/magic-link", response_model=MagicLinkResponse)
async def request_magic_link(request: Request, magic_link_request: MagicLinkRequest):
    """
    Send a magic link to the user's email address.
    """
    try:
        # Get real client IP (considering Cloudflare proxy)
        client_ip = None
        if "CF-Connecting-IP" in request.headers:
            # Cloudflare provides real IP in this header
            client_ip = request.headers["CF-Connecting-IP"]
        elif "X-Forwarded-For" in request.headers:
            # Get first IP from X-Forwarded-For header
            client_ip = request.headers["X-Forwarded-For"].split(",")[0].strip()
        elif "X-Real-IP" in request.headers:
            # Alternative header for real IP
            client_ip = request.headers["X-Real-IP"]
        elif request.client:
            # Fallback to direct connection IP
            client_ip = request.client.host
        
        # Verify Turnstile token first
        turnstile_valid = await TurnstileService.verify_turnstile_token(
            magic_link_request.turnstile_token,
            client_ip
        )
        
        if not turnstile_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="驗證失敗，請重新嘗試。"
            )
        
        # Get base URL from request
        base_url = f"{request.url.scheme}://{request.url.netloc}"
        
        # Extract OIDC state ID from request if present
        oidc_state_id = None
        if hasattr(magic_link_request, 'oidc_state_id') and magic_link_request.oidc_state_id:
            oidc_state_id = magic_link_request.oidc_state_id
        
        # Send magic link (now includes user existence check, IP info, and OIDC state ID)
        result = await MagicLinkService.send_magic_link(
            magic_link_request.email, 
            base_url,
            client_ip,
            oidc_state_id
        )
        
        if result["success"]:
            return MagicLinkResponse(
                message=result["message"],
                success=True
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result["message"]
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in magic link request: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="系統錯誤，請稍後再試。"
        )

@router.get("/verify", response_class=HTMLResponse)
async def verify_magic_link(request: Request, token: str = Query(...)):
    """
    Verify magic link token and handle user login.
    """
    try:
        # Verify token and get token data (including OIDC params)
        token_data = MagicLinkService.verify_magic_token(token)
        
        if not token_data:
            # Token invalid or expired - redirect to login page with error
            return RedirectResponse(url="/?error=invalid_token", status_code=302)
        
        email = token_data.get("email")
        oidc_state_id = token_data.get("oidc_state_id")
        
        # Create user session
        session_data = await MagicLinkService.create_user_session(email)
        
        if not session_data:
            # Session creation failed - redirect to login page with error
            return RedirectResponse(url="/?error=session_failed", status_code=302)
        
        # Create SSO session cookie for seamless future logins
        session_cookie = await create_sso_session(session_data["user_info"])
        
        # Handle OIDC flow if state ID is present
        if oidc_state_id:
            try:
                # Load OIDC state from Redis
                oidc_state_data = redis_client.get(f"oidc_pending:{oidc_state_id}")
                if oidc_state_data:
                    oidc_params = json.loads(oidc_state_data)
                    
                    # Don't delete OIDC state yet - let Outline verify it first
                    # The state will be cleaned up by Redis TTL (15 minutes) or during token exchange
                    logger.debug(f"Keeping OIDC state {oidc_state_id} in Redis for Outline verification")
                    
                    from app.services.oidc_service import OIDCService
                    oidc_service = OIDCService()
                    
                    logger.info(f"Processing OIDC authorization for user {session_data['user_info']['email']}")
                    logger.debug(f"OIDC params: {oidc_params}")
                    logger.debug(f"User session data: {session_data['user_info']}")
                    
                    # Generate authorization code for OIDC client
                    auth_code = oidc_service.generate_authorization_code(
                        client_id=oidc_params["client_id"],
                        user_id=session_data["user_info"]["id"],
                        redirect_uri=oidc_params["redirect_uri"],
                        scope=oidc_params.get("scope", "openid"),
                        nonce=oidc_params.get("nonce"),
                        oidc_state_id=oidc_state_id  # Pass the OIDC state ID for cleanup later
                    )
                    logger.info(f"Generated authorization code: {auth_code[:8]}... for OIDC flow")
                    
                    # Redirect back to OIDC client with authorization code
                    redirect_url = f"{oidc_params['redirect_uri']}?code={auth_code}"
                    if oidc_params.get("state"):
                        redirect_url += f"&state={oidc_params['state']}"
                    
                    logger.info(f"OIDC Magic Link authorization successful, redirecting directly to: {oidc_params['redirect_uri']}")
                    
                    # Direct redirect to OIDC client - no transition page needed
                    response = RedirectResponse(url=redirect_url)
                    
                    # Set session cookie for future SSO
                    response.set_cookie(
                        key="hackit_sso_session",
                        value=session_cookie,
                        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                        httponly=True,
                        secure=True,
                        samesite="lax",
                        domain=".hackit.tw"
                    )
                    return response
                else:
                    logger.warning(f"OIDC state {oidc_state_id} not found in Redis during verification")
            except Exception as e:
                logger.error(f"Error processing OIDC state during verification: {str(e)}")
                # Continue with regular login flow
        
        # Regular SSO success - redirect directly to SSO home page
        logger.info(f"Regular Magic Link verification successful for {session_data['user_info']['email']}, redirecting to SSO home")
        response = RedirectResponse(url="/")
        
        # Set session cookie for future SSO
        response.set_cookie(
            key="hackit_sso_session",
            value=session_cookie,
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            httponly=True,
            secure=True,
            samesite="lax",
            domain=".hackit.tw"
        )
        return response
        
    except Exception as e:
        logger.error(f"Error in magic link verification: {str(e)}")
        # System error - redirect to login page with error
        return RedirectResponse(url="/?error=system_error", status_code=302)

@router.post("/verify-token", response_model=TokenVerifyResponse)
async def verify_token_api(token: str = Body(..., embed=True)):
    """
    API endpoint to verify magic link token (for programmatic access).
    """
    try:
        # Verify token and get token data
        token_data = MagicLinkService.verify_magic_token(token)
        
        if not token_data:
            return TokenVerifyResponse(
                message="Token 無效或已過期",
                success=False
            )
        
        email = token_data.get("email")
        
        # Create user session
        session_data = await MagicLinkService.create_user_session(email)
        
        if not session_data:
            return TokenVerifyResponse(
                message="無法建立用戶會話",
                success=False
            )
        
        return TokenVerifyResponse(
            message="驗證成功",
            success=True,
            access_token=session_data['access_token'],
            token_type=session_data['token_type'],
            user_info=session_data['user_info']
        )
        
    except Exception as e:
        logger.error(f"Error in token verification API: {str(e)}")
        return TokenVerifyResponse(
            message="系統錯誤",
            success=False
        )

@router.post("/sso/verify", response_model=SSOResponse)
async def sso_verify_token(request: Request, sso_request: SSOTokenRequest):
    """
    SSO Token Verification Endpoint
    
    Verifies JWT tokens from HackIt subdomains and returns user information.
    Implements military-grade security with HMAC signatures and domain validation.
    """
    try:
        # Domain validation
        if not validate_domain(sso_request.domain):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Domain not authorized for SSO access"
            )
        
        # Request signature validation (if provided)
        if sso_request.signature and sso_request.timestamp:
            current_time = int(time.time())
            
            # Check timestamp freshness (5 minutes tolerance)
            if abs(current_time - sso_request.timestamp) > 300:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Request timestamp expired"
                )
            
            # Verify signature
            if not verify_sso_signature(
                sso_request.token, 
                sso_request.timestamp, 
                sso_request.domain, 
                sso_request.signature
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid request signature"
                )
        
        # JWT token verification
        try:
            payload = jwt.decode(
                sso_request.token, 
                settings.SECRET_KEY, 
                algorithms=[settings.ALGORITHM]
            )
            
            # Verify token type
            if payload.get("type") != "access":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )
            
            # Token expiration check
            exp = payload.get("exp")
            if exp is None or time.time() > exp:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token expired"
                )
            
        except jwt.PyJWTError as e:
            logger.warning(f"JWT verification failed from {sso_request.domain}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Create sanitized user info (privacy-focused)
        user_info = SSOUserInfo(
            user_id=payload.get("sub", ""),
            email=payload.get("email", ""),
            real_name=payload.get("real_name", ""),
            guild_id=payload.get("guild_id", 0),
            avatar_base64=payload.get("avatar_base64"),
            education_stage=payload.get("education_stage"),
            source=payload.get("source")
        )
        
        # Log successful verification (without sensitive data)
        logger.info(f"SSO verification successful for domain: {sso_request.domain}, user: {payload.get('email', 'unknown')}")
        
        return SSOResponse(
            success=True,
            user=user_info,
            message="Token verified successfully",
            expires_at=payload.get("exp")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SSO verification error from {sso_request.domain}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/sso/config")
async def get_sso_config(domain: str = Query(...)):
    """
    Get SSO Configuration for Client Integration
    
    Returns configuration parameters needed for SSO integration.
    Only available to authorized domains.
    """
    if not validate_domain(domain):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Domain not authorized for SSO access"
        )
    
    return {
        "sso_endpoint": "/auth/sso/verify",
        "login_url": "/auth/",
        "logout_url": "/auth/logout",
        "token_header": "Authorization",
        "token_prefix": "Bearer",
        "signature_required": True,
        "max_age": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "algorithm": "HMAC-SHA256"
    }

@router.post("/sso/refresh")
async def sso_refresh_token(
    request: Request,
    current_user = Depends(get_current_user_from_token)
):
    """
    Refresh SSO Token
    
    Issues a new JWT token for authenticated users.
    Maintains session continuity across HackIt services.
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    # Create new token with refreshed expiration
    new_token_data = {
        "sub": current_user.get("sub"),
        "email": current_user.get("email"),
        "real_name": current_user.get("real_name"),
        "user_id": current_user.get("user_id"),
        "guild_id": current_user.get("guild_id"),
        "avatar_base64": current_user.get("avatar_base64")
    }
    
    from app.auth.jwt_handler import create_access_token
    new_token = create_access_token(new_token_data)
    
    return {
        "access_token": new_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    } 