from typing import Optional, Dict, Any
import logging
from app.core.database import get_database_client
from app.database_client import DatabaseClientError

logger = logging.getLogger(__name__)

async def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Get user by email address using database API."""
    try:
        async with get_database_client() as db_client:
            response = await db_client.get_user_by_email(email)
            if response.get("success"):
                return response.get("data")
            return None
    except DatabaseClientError as e:
        if e.status_code == 404:
            return None
        logger.error(f"Error getting user by email {email}: {e.message}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error getting user by email {email}: {str(e)}")
        return None

async def update_user_login_info(user_id: str, source: str = "magic_link") -> bool:
    """Update user's last login information using database API."""
    try:
        async with get_database_client() as db_client:
            # Update login timestamp
            await db_client.update_user_login(user_id)
            # Update source information
            user_data = {"source": source}
            response = await db_client.update_user(user_id, user_data)
            return response.get("success", False)
    except DatabaseClientError as e:
        logger.error(f"Error updating user login info for {user_id}: {e.message}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error updating user login info for {user_id}: {str(e)}")
        return False

async def create_user(user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Create a new user using database API."""
    try:
        async with get_database_client() as db_client:
            response = await db_client.create_user(user_data)
            if response.get("success"):
                return response.get("data")
            return None
    except DatabaseClientError as e:
        logger.error(f"Error creating user: {e.message}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error creating user: {str(e)}")
        return None

async def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Get user by MongoDB ObjectId using database API."""
    try:
        async with get_database_client() as db_client:
            response = await db_client.get_user_by_id(user_id)
            if response.get("success"):
                return response.get("data")
            return None
    except DatabaseClientError as e:
        if e.status_code == 404:
            return None
        logger.error(f"Error getting user by id {user_id}: {e.message}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error getting user by id {user_id}: {str(e)}")
        return None

async def get_user_by_discord(user_id: int, guild_id: int) -> Optional[Dict[str, Any]]:
    """Get user by Discord user ID and guild ID using database API."""
    try:
        async with get_database_client() as db_client:
            response = await db_client.get_user_by_discord(user_id, guild_id)
            if response.get("success"):
                return response.get("data")
            return None
    except DatabaseClientError as e:
        if e.status_code == 404:
            return None
        logger.error(f"Error getting user by Discord IDs {user_id}/{guild_id}: {e.message}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error getting user by Discord IDs {user_id}/{guild_id}: {str(e)}")
        return None 