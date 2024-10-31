import redis
import os
from dotenv import load_dotenv

load_dotenv()

# Retrieve Redis connection details from environment variables
host = os.getenv("REDIS_HOST")
port = int(os.getenv("REDIS_PORT"))
username = os.getenv("REDIS_USERNAME")
REMOVED = os.getenv("REDIS_PASSWORD")
ssl = os.getenv("REDIS_SSL") == "True"  # Convert string to boolean

# Connect to Redis
redis_client = redis.StrictRedis(
    host=host,
    port=port,
    username=username,
    REMOVED=REMOVED,
    ssl=ssl
)