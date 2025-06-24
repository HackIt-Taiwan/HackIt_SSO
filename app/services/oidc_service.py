import secrets
import time
import jwt
import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
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
        self._generate_or_load_keys()
    
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
        """Get OIDC client by client_id"""
        try:
            client_data = redis_client.get(f"oidc:client:{client_id}")
            if client_data:
                return OIDCClient.model_validate_json(client_data)
            return None
        except Exception as e:
            logger.error(f"Error getting OIDC client {client_id}: {str(e)}")
            return None
    
    def register_client(self, client: OIDCClient) -> bool:
        """Register a new OIDC client"""
        try:
            redis_client.set(
                f"oidc:client:{client.client_id}",
                client.model_dump_json(),
                ex=86400 * 365  # 1 year expiry
            )
            logger.info(f"Registered OIDC client: {client.client_id}")
            return True
        except Exception as e:
            logger.error(f"Error registering OIDC client: {str(e)}")
            return False
    
    def generate_authorization_code(self, client_id: str, user_id: str, 
                                  redirect_uri: str, scope: str, 
                                  nonce: Optional[str] = None) -> str:
        """Generate authorization code"""
        code = secrets.token_urlsafe(32)
        code_data = {
            "client_id": client_id,
            "user_id": user_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "nonce": nonce,
            "created_at": int(time.time())
        }
        
        # Store code for 10 minutes
        redis_client.set(
            f"oidc:auth_code:{code}",
            json.dumps(code_data),
            ex=600
        )
        
        logger.info(f"Generated authorization code for client {client_id}, user {user_id}")
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
            
            # Delete used code
            redis_client.delete(f"oidc:auth_code:{code}")
            
            # Generate tokens
            access_token = self._generate_access_token(code_data["user_id"], client_id, code_data["scope"])
            id_token = await self._generate_id_token(code_data["user_id"], client_id, code_data.get("nonce"))
            refresh_token = self._generate_refresh_token(code_data["user_id"], client_id)
            
            return OIDCTokenResponse(
                access_token=access_token,
                id_token=id_token,
                refresh_token=refresh_token,
                expires_in=3600,
                scope=code_data["scope"]
            )
            
        except Exception as e:
            logger.error(f"Error exchanging code for tokens: {str(e)}")
            return None
    
    def _generate_access_token(self, user_id: str, client_id: str, scope: str) -> str:
        """Generate access token"""
        payload = {
            "sub": user_id,
            "aud": client_id,
            "scope": scope,
            "iss": self.issuer,
            "exp": int(time.time()) + 3600,  # 1 hour
            "iat": int(time.time()),
            "token_type": "access_token"
        }
        
        return jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": self.kid})
    
    async def _generate_id_token(self, user_id: str, client_id: str, nonce: Optional[str] = None) -> str:
        """Generate ID token with user information"""
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
            
            payload = {
                "iss": self.issuer,
                "sub": user_id,
                "aud": client_id,
                "exp": int(time.time()) + 3600,  # 1 hour
                "iat": int(time.time()),
                "auth_time": int(time.time()),
                "email": user.get("email"),
                "email_verified": True,
                "name": full_name,
                "given_name": given_name,
                "family_name": family_name,
                "picture": user.get("avatar_base64"),
                "preferred_username": user.get("email"),
                "locale": "zh-TW"
            }
            
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
        
        # Store refresh token for 30 days
        redis_client.set(
            f"oidc:refresh_token:{refresh_token}",
            json.dumps(token_data),
            ex=86400 * 30
        )
        
        return refresh_token
    
    def verify_access_token(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode access token"""
        try:
            payload = jwt.decode(
                access_token,
                self.public_key,
                algorithms=["RS256"],
                issuer=self.issuer
            )
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
            
            return OIDCUserInfo(
                sub=user_id,
                name=full_name,
                given_name=given_name,
                family_name=family_name,
                email=user.get("email"),
                email_verified=True,
                picture=user.get("avatar_base64"),
                preferred_username=user.get("email"),
                locale="zh-TW",
                updated_at=int(time.time())
            )
            
        except Exception as e:
            logger.error(f"Error getting userinfo: {str(e)}")
            return None
    
    def get_jwks(self) -> JWKSet:
        """Get JSON Web Key Set"""
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
            token_data_json = redis_client.get(f"oidc:refresh_token:{refresh_token}")
            if not token_data_json:
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