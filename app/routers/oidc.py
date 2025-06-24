from fastapi import APIRouter, Depends, HTTPException, Request, Form, Query
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, Dict, Any
import base64
import logging
import json

from app.services.oidc_service import OIDCService
from app.schemas.oidc import (
    OIDCDiscoveryResponse, OIDCAuthorizationRequest, 
    OIDCTokenRequest, OIDCClient
)
from app.core.config import settings
from app.auth.jwt_handler import decode_access_token
from app.core.database import redis_client

router = APIRouter()
security = HTTPBearer()
logger = logging.getLogger(__name__)

# Initialize OIDC service
oidc_service = OIDCService()

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

@router.get("/.well-known/openid-configuration", response_model=OIDCDiscoveryResponse)
async def oidc_discovery():
    """OIDC Discovery Document (RFC 8414)"""
    base_url = settings.OIDC_ISSUER
    
    return OIDCDiscoveryResponse(
        issuer=settings.OIDC_ISSUER,
        authorization_endpoint=f"{base_url}/oidc/authorize",
        token_endpoint=f"{base_url}/oidc/token",
        userinfo_endpoint=f"{base_url}/oidc/userinfo",
        jwks_uri=f"{base_url}/oidc/jwks",
        end_session_endpoint=f"{base_url}/oidc/endsession"
    )

@router.get("/oidc/jwks")
async def jwks_endpoint():
    """JSON Web Key Set endpoint"""
    try:
        jwks = oidc_service.get_jwks()
        return jwks.model_dump()
    except Exception as e:
        logger.error(f"Error serving JWKS: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/oidc/authorize")
async def authorization_endpoint(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(default="openid"),
    state: Optional[str] = Query(None),
    nonce: Optional[str] = Query(None),
    prompt: Optional[str] = Query(None),
    request: Request = None
):
    """OIDC Authorization Endpoint"""
    try:
        # Validate client
        client = oidc_service.get_client(client_id)
        if not client:
            raise HTTPException(status_code=400, detail="Invalid client_id")
        
        if redirect_uri not in client.redirect_uris:
            raise HTTPException(status_code=400, detail="Invalid redirect_uri")
        
        # Check if user is already authenticated via session cookie
        user_session = await check_user_session(request)
        if user_session:
            user_id = user_session.get("user_id")
            if user_id:
                logger.info(f"User {user_session.get('email')} already authenticated, generating OIDC auth code")
                
                # User is authenticated, generate authorization code
                auth_code = oidc_service.generate_authorization_code(
                    client_id=client_id,
                    user_id=user_id,
                    redirect_uri=redirect_uri,
                    scope=scope,
                    nonce=nonce
                )
                
                # Redirect back to client with authorization code
                redirect_url = f"{redirect_uri}?code={auth_code}"
                if state:
                    redirect_url += f"&state={state}"
                
                logger.info(f"OIDC seamless login: redirecting to {redirect_uri}")
                return RedirectResponse(url=redirect_url)
        
        # User not authenticated, redirect to SSO login
        sso_login_url = f"{settings.OIDC_ISSUER}/auth/"
        sso_params = {
            "oidc_client_id": client_id,
            "oidc_redirect_uri": redirect_uri,
            "oidc_scope": scope,
            "oidc_state": state,
            "oidc_nonce": nonce
        }
        
        # Build login URL with OIDC parameters
        params_str = "&".join([f"{k}={v}" for k, v in sso_params.items() if v])
        full_login_url = f"{sso_login_url}?{params_str}"
        
        return RedirectResponse(url=full_login_url)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in authorization endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/oidc/token")
async def token_endpoint(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    request: Request = None
):
    """OIDC Token Endpoint"""
    try:
        # Handle client authentication via Authorization header
        if not client_id or not client_secret:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Basic "):
                try:
                    encoded_credentials = auth_header.split(" ")[1]
                    decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
                    client_id, client_secret = decoded_credentials.split(":", 1)
                except Exception as e:
                    logger.warning(f"Error decoding basic auth: {str(e)}")
                    raise HTTPException(status_code=400, detail="Invalid client authentication")
        
        if not client_id or not client_secret:
            raise HTTPException(status_code=400, detail="Client authentication required")
        
        if grant_type == "authorization_code":
            if not code or not redirect_uri:
                raise HTTPException(status_code=400, detail="Missing required parameters")
            
            token_response = await oidc_service.exchange_code_for_tokens(
                code=code,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri
            )
            
            if not token_response:
                raise HTTPException(status_code=400, detail="Invalid authorization code")
            
            return token_response.model_dump()
            
        elif grant_type == "refresh_token":
            if not refresh_token:
                raise HTTPException(status_code=400, detail="Missing refresh_token")
            
            token_response = await oidc_service.refresh_access_token(
                refresh_token=refresh_token,
                client_id=client_id,
                client_secret=client_secret
            )
            
            if not token_response:
                raise HTTPException(status_code=400, detail="Invalid refresh token")
            
            return token_response.model_dump()
            
        else:
            raise HTTPException(status_code=400, detail="Unsupported grant_type")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in token endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/oidc/userinfo")
async def userinfo_endpoint(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """OIDC UserInfo Endpoint"""
    try:
        access_token = credentials.credentials
        userinfo = await oidc_service.get_userinfo(access_token)
        
        if not userinfo:
            raise HTTPException(status_code=401, detail="Invalid access token")
        
        return userinfo.model_dump(exclude_none=True)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in userinfo endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/oidc/endsession")
@router.post("/oidc/endsession")
async def end_session_endpoint(
    request: Request,
    id_token_hint: Optional[str] = Query(None),
    post_logout_redirect_uri: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    client_id: Optional[str] = Query(None)
):
    """OIDC End Session Endpoint (RP-Initiated Logout)"""
    try:
        # Validate post_logout_redirect_uri if provided
        if post_logout_redirect_uri and client_id:
            client = oidc_service.get_client(client_id)
            if client and post_logout_redirect_uri not in client.redirect_uris:
                # For logout, we're more lenient - just log warning
                logger.warning(f"Post-logout redirect URI not in whitelist: {post_logout_redirect_uri}")
        
        # Get current session from cookie
        session_cookie = request.cookies.get("hackit_sso_session")
        if session_cookie:
            # Clear the session
            try:
                redis_client.delete(f"session:{session_cookie}")
                logger.info(f"OIDC logout: cleared SSO session {session_cookie}")
            except Exception as e:
                logger.error(f"Error clearing session during OIDC logout: {str(e)}")
        
        # Prepare redirect response
        if post_logout_redirect_uri:
            redirect_url = post_logout_redirect_uri
            if state:
                separator = "&" if "?" in redirect_url else "?"
                redirect_url = f"{redirect_url}{separator}state={state}"
            
            # Clear session cookie and redirect
            response = RedirectResponse(url=redirect_url)
            response.delete_cookie(
                key="hackit_sso_session",
                domain=f".{settings.SSO_DOMAIN}",
                path="/",
                secure=True,
                httponly=True,
                samesite="lax"
            )
            logger.info(f"OIDC logout: redirecting to {post_logout_redirect_uri}")
            return response
        else:
            # No redirect URI provided, show logout confirmation
            response = JSONResponse({
                "message": "Logout successful",
                "logged_out": True
            })
            response.delete_cookie(
                key="hackit_sso_session",
                domain=f".{settings.SSO_DOMAIN}",
                path="/",
                secure=True,
                httponly=True,
                samesite="lax"
            )
            return response
            
    except Exception as e:
        logger.error(f"Error in OIDC end session endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/oidc/register")
async def register_client(
    client: OIDCClient,
    request: Request
):
    """Register OIDC Client (Admin Only)"""
    try:
        # Get admin key from Authorization header
        auth_header = request.headers.get("Authorization")
        provided_key = None
        
        if auth_header and auth_header.startswith("Bearer "):
            provided_key = auth_header.split(" ")[1]
        
        # Verify admin key
        if not provided_key or not settings.OIDC_ADMIN_KEY:
            raise HTTPException(
                status_code=401, 
                detail="Admin authentication required. Provide Authorization: Bearer <OIDC_ADMIN_KEY> header."
            )
        
        if provided_key != settings.OIDC_ADMIN_KEY:
            logger.warning(f"Invalid OIDC admin key attempt from {request.client.host}")
            raise HTTPException(status_code=403, detail="Invalid admin key")
        
        # Register client
        result = oidc_service.register_client(client)
        if result.get("success"):
            logger.info(f"OIDC client '{client.client_id}' registered by admin from {request.client.host}")
            return {
                "message": result.get("message"),
                "client_id": client.client_id,
                "env_variable": result.get("env_variable"),
                "instructions": "Add the env_variable to your .env file and restart the service"
            }
        else:
            raise HTTPException(status_code=400, detail=result.get("message", "Failed to register client"))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering OIDC client: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/oidc/clients/{client_id}")
async def get_client_info(client_id: str):
    """Get OIDC Client Information (for debugging)"""
    client = oidc_service.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    # Return client info without secret
    return {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
        "grant_types": client.grant_types,
        "response_types": client.response_types,
        "scope": client.scope
    } 