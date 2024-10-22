# logger.py
import logging
import os
from logging.handlers import RotatingFileHandler

# Create a logger
logger = logging.getLogger('app_logger')

# Check if we are running under Gunicorn
if 'gunicorn' in os.environ.get('SERVER_SOFTWARE', ''):
    gunicorn_logger = logging.getLogger('gunicorn.error')
    logger.handlers = gunicorn_logger.handlers
    logger.setLevel(gunicorn_logger.level)
    logger.info("Logger configured to use Gunicorn logs.")
else:
    # For local development, set up rotating file handler
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    file_handler = logging.handlers.RotatingFileHandler('logs/flask_app.log', maxBytes=10240, backupCount=10)
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.setLevel(logging.INFO)
    logger.info("Logger configured for local development.")
