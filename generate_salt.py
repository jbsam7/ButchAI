import os
from logger import logger

# Generate the random salt
salt = os.urandom(16).hex()
logger.info(salt)
