import redis
from .config import settings
from ..database_client import DatabaseClient

def get_redis_client():
    """Returns a Redis client instance."""
    return redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD,
        db=settings.REDIS_DB,
        decode_responses=True  # To get strings from Redis, not bytes
    )

def get_database_client():
    """Returns a database service client instance."""
    return DatabaseClient(
        base_url=settings.DATABASE_SERVICE_URL,
        api_secret_key=settings.DATABASE_SERVICE_SECRET
    )

redis_client = get_redis_client() 