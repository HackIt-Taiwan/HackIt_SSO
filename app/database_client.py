import httpx
import hmac
import hashlib
import time
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager
import logging

logger = logging.getLogger(__name__)

class DatabaseClientError(Exception):
    """Custom exception for database client errors."""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message

class DatabaseClient:
    """Async HTTP client for HackIt centralized database service."""
    
    def __init__(self, base_url: str, api_secret_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_secret_key = api_secret_key
        self._client: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self._client = httpx.AsyncClient(timeout=30.0)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    def _create_signature(self, method: str, path: str) -> Dict[str, str]:
        """Create HMAC signature for authentication."""
        timestamp = int(time.time())
        message = f"{method.upper()}:{path}:{timestamp}"
        signature = hmac.new(
            self.api_secret_key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return {
            'X-API-Timestamp': str(timestamp),
            'X-API-Signature': signature,
            'Content-Type': 'application/json'
        }
    
    async def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated HTTP request."""
        if not self._client:
            raise DatabaseClientError("Client not initialized. Use async context manager.")
        
        headers = self._create_signature(method, path)
        url = f"{self.base_url}{path}"
        
        try:
            response = await self._client.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            error_msg = f"HTTP {e.response.status_code}: {e.response.text}"
            raise DatabaseClientError(error_msg, e.response.status_code)
        except httpx.RequestError as e:
            raise DatabaseClientError(f"Request failed: {str(e)}")
        except Exception as e:
            raise DatabaseClientError(f"Unexpected error: {str(e)}")
    
    # User Management Methods
    
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user."""
        return await self._request('POST', '/users/', json=user_data)
    
    async def get_user_by_id(self, user_id: str) -> Dict[str, Any]:
        """Get user by MongoDB ObjectId."""
        return await self._request('GET', f'/users/{user_id}')
    
    async def get_user_by_email(self, email: str) -> Dict[str, Any]:
        """Get user by email address."""
        return await self._request('GET', f'/users/email/{email}')
    
    async def get_user_by_discord(self, user_id: int, guild_id: int) -> Dict[str, Any]:
        """Get user by Discord user ID and guild ID."""
        return await self._request('GET', f'/users/discord/{user_id}/{guild_id}')
    
    async def update_user(self, user_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user information."""
        return await self._request('PUT', f'/users/{user_id}', json=update_data)
    
    async def delete_user(self, user_id: str) -> Dict[str, Any]:
        """Delete user."""
        return await self._request('DELETE', f'/users/{user_id}')
    
    async def query_users(self, query_data: Dict[str, Any]) -> Dict[str, Any]:
        """Advanced user query with filters."""
        return await self._request('POST', '/users/query', json=query_data)
    
    async def list_users(self, limit: int = 10, offset: int = 0, 
                        active_only: bool = False, public_only: bool = False) -> Dict[str, Any]:
        """List users with pagination."""
        params = {
            'limit': limit,
            'offset': offset,
            'active_only': active_only,
            'public_only': public_only
        }
        return await self._request('GET', '/users/', params=params)
    
    # User Status Management
    
    async def activate_user(self, user_id: str) -> Dict[str, Any]:
        """Activate user account."""
        return await self._request('PATCH', f'/users/{user_id}/activate')
    
    async def deactivate_user(self, user_id: str) -> Dict[str, Any]:
        """Deactivate user account."""
        return await self._request('PATCH', f'/users/{user_id}/deactivate')
    
    async def update_user_login(self, user_id: str) -> Dict[str, Any]:
        """Update user's last login timestamp."""
        return await self._request('PATCH', f'/users/{user_id}/login')
    
    # Tag Management
    
    async def add_user_tag(self, user_id: str, tag: str) -> Dict[str, Any]:
        """Add tag to user."""
        return await self._request('POST', f'/users/{user_id}/tags', json={'tag': tag})
    
    async def remove_user_tag(self, user_id: str, tag: str) -> Dict[str, Any]:
        """Remove tag from user."""
        return await self._request('DELETE', f'/users/{user_id}/tags', json={'tag': tag})
    
    # Search Operations
    
    async def search_users_by_name(self, name: str, limit: int = 20) -> Dict[str, Any]:
        """Search users by name."""
        return await self._request('GET', f'/users/search/name/{name}', params={'limit': limit})
    
    async def get_users_by_tag(self, tag: str, limit: int = 50) -> Dict[str, Any]:
        """Get users by tag."""
        return await self._request('GET', f'/users/tag/{tag}', params={'limit': limit})
    
    # Analytics
    
    async def get_user_statistics(self) -> Dict[str, Any]:
        """Get user statistics."""
        return await self._request('GET', '/users/analytics/statistics')
    
    # Bulk Operations
    
    async def bulk_update_users(self, user_ids: List[str], update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Bulk update multiple users."""
        data = {
            'user_ids': user_ids,
            'update_data': update_data
        }
        return await self._request('PUT', '/users/bulk', json=data)
    
    # Health Check
    
    async def health_check(self) -> Dict[str, Any]:
        """Check service health."""
        return await self._request('GET', '/health')
    
    # Helper Methods
    
    async def get_user_simple(self, identifier, guild_id=None) -> Optional[Dict[str, Any]]:
        """
        Simple user retrieval by various identifiers.
        
        Args:
            identifier: Email (str), Discord user ID (int), or MongoDB ObjectId (str)
            guild_id: Discord guild ID (required if identifier is Discord user ID)
        
        Returns:
            User data or None if not found
        """
        try:
            if isinstance(identifier, str) and '@' in identifier:
                # Email address
                response = await self.get_user_by_email(identifier)
            elif isinstance(identifier, int) and guild_id is not None:
                # Discord user ID
                response = await self.get_user_by_discord(identifier, guild_id)
            elif isinstance(identifier, str):
                # MongoDB ObjectId
                response = await self.get_user_by_id(identifier)
            else:
                return None
            
            return response.get('data') if response.get('success') else None
            
        except DatabaseClientError as e:
            if e.status_code == 404:
                return None
            logger.error(f"Error in get_user_simple: {e.message}")
            return None
    
    async def create_or_update_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create user or update if exists.
        
        Args:
            user_data: User information including user_id, guild_id, email
        
        Returns:
            Response with user data and status
        """
        try:
            # Check if user exists by email or Discord IDs
            existing_user = None
            
            if 'email' in user_data:
                existing_user = await self.get_user_simple(user_data['email'])
            
            if not existing_user and 'user_id' in user_data and 'guild_id' in user_data:
                existing_user = await self.get_user_simple(user_data['user_id'], user_data['guild_id'])
            
            if existing_user:
                # Update existing user
                user_id = existing_user['id']
                response = await self.update_user(user_id, user_data)
                return {
                    'success': True,
                    'action': 'updated',
                    'data': response.get('data')
                }
            else:
                # Create new user
                response = await self.create_user(user_data)
                return {
                    'success': True,
                    'action': 'created',
                    'data': response.get('data')
                }
                
        except DatabaseClientError as e:
            return {
                'success': False,
                'action': 'error',
                'message': e.message
            } 