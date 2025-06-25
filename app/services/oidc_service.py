import secrets
import time
import jwt
import json
import base64
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from authlib.integrations.base_client import OAuthError
from app.core.config import settings
from app.core.database import redis_client
from app.schemas.oidc import (
    OIDCClient, OIDCUserInfo, IDTokenClaims, 
    OIDCTokenResponse, JWKSet
)
import logging

logger = logging.getLogger(__name__)

class OIDCService:
    """OIDC Provider Service"""
    
    def __init__(self):
        self.issuer = settings.OIDC_ISSUER
        self.private_key = None
        self.public_key = None
        self.kid = "hackit-sso-key-1"
        self._keys_initialized = False
    
    def _ensure_keys_initialized(self):
        """Lazy initialization of RSA keys with fallback"""
        if self._keys_initialized:
            return
            
        try:
            self._generate_or_load_keys()
            self._keys_initialized = True
        except Exception as e:
            logger.error(f"Error initializing OIDC keys: {str(e)}")
            # Fallback: generate temporary keys in memory
            self._generate_temporary_keys()
            self._keys_initialized = True
    
    def _generate_temporary_keys(self):
        """Generate temporary keys in memory when Redis is unavailable"""
        logger.warning("Redis unavailable, generating temporary OIDC keys in memory")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def _generate_or_load_keys(self):
        """Generate or load RSA keys for JWT signing"""
        try:
            # Try to load existing keys from Redis
            private_key_pem = redis_client.get("oidc:private_key")
            public_key_pem = redis_client.get("oidc:public_key")
            
            if private_key_pem and public_key_pem:
                self.private_key = serialization.load_pem_private_key(
                    private_key_pem.encode('utf-8'),
                    password=None
                )
                self.public_key = serialization.load_pem_public_key(
                    public_key_pem.encode('utf-8')
                )
                logger.info("Loaded existing OIDC keys from Redis")
            else:
                # Generate new keys
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                self.public_key = self.private_key.public_key()
                
                # Store keys in Redis
                private_pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                
                public_pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                redis_client.set("oidc:private_key", private_pem)
                redis_client.set("oidc:public_key", public_pem)
                logger.info("Generated new OIDC keys and stored in Redis")
                
        except Exception as e:
            logger.error(f"Error loading/generating OIDC keys: {str(e)}")
            raise
    
    def get_client(self, client_id: str) -> Optional[OIDCClient]:
        """Get OIDC client by client_id from Base64 encoded environment variable"""
        try:
            # Load clients from Base64 encoded environment variable
            clients_base64 = settings.OIDC_CLIENTS
            if not clients_base64 or clients_base64 == "W10=":  # W10= is Base64 for "[]"
                logger.warning(f"No OIDC clients configured in environment")
                return None
            
            # Decode Base64 to JSON string
            try:
                clients_json = base64.b64decode(clients_base64).decode('utf-8')
            except Exception as e:
                logger.error(f"Error decoding Base64 OIDC_CLIENTS: {str(e)}")
                return None
                
            clients_data = json.loads(clients_json)
            
            # Find client by ID
            for client_data in clients_data:
                if client_data.get("client_id") == client_id:
                    return OIDCClient(**client_data)
            
            logger.warning(f"OIDC client not found: {client_id}")
            return None
            
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing OIDC_CLIENTS JSON: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error getting OIDC client {client_id}: {str(e)}")
            return None
    
    def register_client(self, client: OIDCClient) -> dict:
        """Register a new OIDC client - returns Base64 encoded environment variable for manual addition"""
        try:
            # Load existing clients from Base64
            existing_clients = []
            clients_base64 = settings.OIDC_CLIENTS
            if clients_base64 and clients_base64 != "W10=":  # W10= is Base64 for "[]"
                try:
                    clients_json = base64.b64decode(clients_base64).decode('utf-8')
                    existing_clients = json.loads(clients_json)
                except Exception:
                    logger.warning("Invalid OIDC_CLIENTS format, starting fresh")
                    existing_clients = []
            
            # Check if client already exists
            for existing_client in existing_clients:
                if existing_client.get("client_id") == client.client_id:
                    logger.warning(f"OIDC client {client.client_id} already exists")
                    return {
                        "success": False,
                        "message": f"Client '{client.client_id}' already exists in configuration"
                    }
            
            # Add new client
            new_client_data = client.model_dump()
            existing_clients.append(new_client_data)
            
            # Generate new environment variable value (Base64 encoded)
            new_json = json.dumps(existing_clients, separators=(',', ':'))
            new_base64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
            
            logger.info(f"Generated OIDC client registration for: {client.client_id}")
            return {
                "success": True,
                "message": "Client registration prepared",
                "client_id": client.client_id,
                "env_variable": f"OIDC_CLIENTS={new_base64}",
                "json_preview": new_json  # For debugging
            }
            
        except Exception as e:
            logger.error(f"Error preparing OIDC client registration: {str(e)}")
            return {
                "success": False,
                "message": f"Error preparing registration: {str(e)}"
            }
    
    def generate_authorization_code(self, client_id: str, user_id: str, 
                                  redirect_uri: str, scope: str, 
                                  nonce: Optional[str] = None, 
                                  oidc_state_id: Optional[str] = None) -> str:
        """Generate authorization code"""
        code = secrets.token_urlsafe(32)
        code_data = {
            "client_id": client_id,
            "user_id": user_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "nonce": nonce,
            "oidc_state_id": oidc_state_id,  # Store the OIDC state ID for cleanup
            "created_at": int(time.time())
        }
        
        try:
            # Store code for 10 minutes
            redis_key = f"oidc:auth_code:{code}"
            redis_client.set(
                redis_key,
                json.dumps(code_data),
                ex=600
            )
            logger.info(f"Generated authorization code for client {client_id}, user {user_id}")
            logger.debug(f"Stored auth code data in Redis key: {redis_key}, data: {code_data}")
            
            # Verify storage immediately
            stored_data = redis_client.get(redis_key)
            if stored_data:
                logger.debug(f"Authorization code successfully stored and verified in Redis")
            else:
                logger.error(f"Failed to verify authorization code storage in Redis")
                
        except Exception as e:
            logger.error(f"Error storing authorization code: {str(e)}")
            raise
        
        return code
    
    async def exchange_code_for_tokens(self, code: str, client_id: str, 
                               client_secret: str, redirect_uri: str) -> Optional[OIDCTokenResponse]:
        """Exchange authorization code for tokens"""
        try:
            # Get code data
            code_data_json = redis_client.get(f"oidc:auth_code:{code}")
            if not code_data_json:
                logger.warning(f"Authorization code not found or expired: {code}")
                return None
            
            code_data = json.loads(code_data_json)
            
            # Check if code has already been used (for idempotency)
            if code_data.get("used"):
                logger.info(f"Authorization code already used, returning cached tokens: {code[:8]}...")
                # Return cached tokens if available
                cached_tokens = code_data.get("cached_tokens")
                if cached_tokens:
                    return OIDCTokenResponse(**cached_tokens)
                else:
                    logger.warning(f"Authorization code used but no cached tokens found: {code}")
                    return None
            
            # Verify client and redirect URI
            client = self.get_client(client_id)
            if not client or client.client_secret != client_secret:
                logger.warning(f"Invalid client credentials for {client_id}")
                return None
            
            if redirect_uri not in client.redirect_uris:
                logger.warning(f"Invalid redirect URI {redirect_uri} for client {client_id}")
                return None
            
            if code_data["client_id"] != client_id or code_data["redirect_uri"] != redirect_uri:
                logger.warning(f"Code data mismatch for client {client_id}")
                return None
            
            # Mark code as used instead of deleting (for idempotency)
            code_data["used"] = True
            code_data["used_at"] = int(time.time())
            redis_client.set(
                f"oidc:auth_code:{code}",
                json.dumps(code_data),
                ex=300  # Keep for 5 minutes to handle duplicate requests
            )
            logger.debug(f"Marked authorization code {code[:8]}... as used")
            
            # Clean up OIDC state if present
            oidc_state_id = code_data.get("oidc_state_id")
            if oidc_state_id:
                try:
                    redis_client.delete(f"oidc_pending:{oidc_state_id}")
                    logger.debug(f"Cleaned up OIDC state {oidc_state_id} after successful token exchange")
                except Exception as e:
                    logger.warning(f"Failed to clean up OIDC state {oidc_state_id}: {str(e)}")
            
            # Generate tokens
            access_token = self._generate_access_token(code_data["user_id"], client_id, code_data["scope"])
            id_token = await self._generate_id_token(code_data["user_id"], client_id, code_data.get("nonce"))
            refresh_token = self._generate_refresh_token(code_data["user_id"], client_id)
            
            # Create token response
            token_response = OIDCTokenResponse(
                access_token=access_token,
                id_token=id_token,
                refresh_token=refresh_token,
                expires_in=3600,
                scope=code_data["scope"]
            )
            
            # Cache tokens for idempotency (in case of duplicate requests)
            try:
                code_data["cached_tokens"] = {
                    "access_token": access_token,
                    "id_token": id_token,
                    "refresh_token": refresh_token,
                    "expires_in": 3600,
                    "scope": code_data["scope"]
                }
                redis_client.set(
                    f"oidc:auth_code:{code}",
                    json.dumps(code_data),
                    ex=300  # Keep for 5 minutes
                )
                logger.debug(f"Cached tokens for authorization code {code[:8]}...")
            except Exception as cache_error:
                logger.warning(f"Failed to cache tokens: {cache_error}")
                # Continue anyway - primary function still works
            
            return token_response
            
        except Exception as e:
            logger.error(f"Error exchanging code for tokens: {str(e)}")
            return None
    
    def _generate_access_token(self, user_id: str, client_id: str, scope: str) -> str:
        """Generate access token"""
        self._ensure_keys_initialized()
        
        payload = {
            "sub": user_id,
            "aud": [client_id, self.issuer],  # Include both client_id and issuer as audience
            "scope": scope,
            "iss": self.issuer,
            "exp": int(time.time()) + 3600,  # 1 hour
            "iat": int(time.time()),
            "token_type": "access_token",
            "client_id": client_id  # Add client_id for additional context
        }
        
        logger.debug(f"Generated access token for user {user_id}, client {client_id}, scope: {scope}")
        return jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": self.kid})
    
    async def _generate_id_token(self, user_id: str, client_id: str, nonce: Optional[str] = None) -> str:
        """Generate ID token with user information"""
        self._ensure_keys_initialized()
        
        from app.crud.user_api import get_user_by_id
        
        try:
            # Get user information
            user = await get_user_by_id(user_id)
            if not user:
                raise ValueError(f"User not found: {user_id}")
            
            # Parse name into given_name and family_name
            full_name = user.get("real_name", "")
            name_parts = full_name.split(" ", 1) if full_name else ["", ""]
            given_name = name_parts[0] if len(name_parts) > 0 else ""
            family_name = name_parts[1] if len(name_parts) > 1 else ""
            
            # Ensure email is not None - this is critical for Outline
            user_email = user.get("email")
            if not user_email:
                logger.error(f"User {user_id} has no email address - this will cause OIDC authentication to fail")
                raise ValueError(f"User {user_id} has no email address")
            
            # Generate avatar URL using Database API
            from app.core.config import get_avatar_url
            avatar_url = get_avatar_url(user_id)
            
            payload = {
                "iss": self.issuer,
                "sub": user_id,
                "aud": client_id,
                "exp": int(time.time()) + 3600,  # 1 hour
                "iat": int(time.time()),
                "auth_time": int(time.time()),
                "email": user_email,  # Use validated email
                "email_verified": True,
                "name": full_name,
                "given_name": given_name,
                "family_name": family_name,
                "preferred_username": user_email,  # Use validated email
                "locale": "zh-TW"
            }
            
            # Include picture URL (always valid with Database API)
            payload["picture"] = avatar_url
            
            if nonce:
                payload["nonce"] = nonce
            
            return jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": self.kid})
            
        except Exception as e:
            logger.error(f"Error generating ID token: {str(e)}")
            raise
    
    def _generate_refresh_token(self, user_id: str, client_id: str) -> str:
        """Generate refresh token"""
        refresh_token = secrets.token_urlsafe(32)
        token_data = {
            "user_id": user_id,
            "client_id": client_id,
            "created_at": int(time.time())
        }
        
        try:
            # Store refresh token for 30 days
            redis_client.set(
                f"oidc:refresh_token:{refresh_token}",
                json.dumps(token_data),
                ex=86400 * 30
            )
        except Exception as e:
            logger.error(f"Error storing refresh token: {str(e)}")
            # Continue without storing - token still generated
        
        return refresh_token
    
    def verify_access_token(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode access token"""
        self._ensure_keys_initialized()
        
        try:
            # Don't verify audience for access tokens - different from ID tokens
            payload = jwt.decode(
                access_token,
                self.public_key,
                algorithms=["RS256"],
                issuer=self.issuer,
                options={"verify_aud": False}  # Disable audience verification for access tokens
            )
            logger.debug(f"Access token verified successfully for user {payload.get('sub')}")
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Access token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid access token: {str(e)}")
            return None
    
    async def get_userinfo(self, access_token: str) -> Optional[OIDCUserInfo]:
        """Get user information from access token"""
        from app.crud.user_api import get_user_by_id
        
        try:
            token_payload = self.verify_access_token(access_token)
            if not token_payload:
                return None
            
            user_id = token_payload.get("sub")
            if not user_id:
                return None
            
            user = await get_user_by_id(user_id)
            if not user:
                return None
            
            # Parse name
            full_name = user.get("real_name", "")
            name_parts = full_name.split(" ", 1) if full_name else ["", ""]
            given_name = name_parts[0] if len(name_parts) > 0 else ""
            family_name = name_parts[1] if len(name_parts) > 1 else ""
            
            # Ensure email is not None for UserInfo endpoint
            user_email = user.get("email")
            if not user_email:
                logger.error(f"User {user_id} has no email address in UserInfo request")
                return None
            
            # Generate avatar URL using Database API
            from app.core.config import get_avatar_url
            avatar_url = get_avatar_url(user_id)
            
            return OIDCUserInfo(
                sub=user_id,
                name=full_name,
                given_name=given_name,
                family_name=family_name,
                email=user_email,  # Use validated email
                email_verified=True,
                picture=avatar_url,  # Database API avatar URL
                preferred_username=user_email,  # Use validated email
                locale="zh-TW",
                updated_at=int(time.time())
            )
            
        except Exception as e:
            logger.error(f"Error getting userinfo: {str(e)}")
            return None
    
    def get_jwks(self) -> JWKSet:
        """Get JSON Web Key Set"""
        self._ensure_keys_initialized()
        
        try:
            # Get public key numbers
            public_numbers = self.public_key.public_numbers()
            
            # Convert to JWK format
            from authlib.jose import JsonWebKey
            jwk = JsonWebKey.import_key(self.public_key)
            jwk_dict = jwk.as_dict()
            jwk_dict.update({
                "kid": self.kid,
                "use": "sig",
                "alg": "RS256"
            })
            
            return JWKSet(keys=[jwk_dict])
            
        except Exception as e:
            logger.error(f"Error generating JWKS: {str(e)}")
            raise
    
    async def refresh_access_token(self, refresh_token: str, client_id: str, 
                           client_secret: str) -> Optional[OIDCTokenResponse]:
        """Refresh access token using refresh token"""
        try:
            # Verify client
            client = self.get_client(client_id)
            if not client or client.client_secret != client_secret:
                return None
            
            # Get refresh token data
            try:
                token_data_json = redis_client.get(f"oidc:refresh_token:{refresh_token}")
                if not token_data_json:
                    return None
            except Exception as e:
                logger.error(f"Error accessing refresh token from Redis: {str(e)}")
                return None
            
            token_data = json.loads(token_data_json)
            
            if token_data["client_id"] != client_id:
                return None
            
            # Generate new tokens
            access_token = self._generate_access_token(
                token_data["user_id"], 
                client_id, 
                "openid profile email"
            )
            
            id_token = await self._generate_id_token(token_data["user_id"], client_id)
            
            return OIDCTokenResponse(
                access_token=access_token,
                id_token=id_token,
                refresh_token=refresh_token,  # Keep same refresh token
                expires_in=3600,
                scope="openid profile email"
            )
            
        except Exception as e:
            logger.error(f"Error refreshing token: {str(e)}")
            return None 