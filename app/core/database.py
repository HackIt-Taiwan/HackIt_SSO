import redis
from .config import settings
from ..database_client import DatabaseClient

def get_database_client():
    """Returns a database service client instance."""
    return DatabaseClient(
        base_url=settings.DATABASE_SERVICE_URL,
        api_secret_key=settings.DATABASE_SERVICE_SECRET
    )

# Redis client for session management
redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True) 