import random
from datetime import datetime, timedelta
import smtplib
import redis
from redis_config import redis_client
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os
from itsdangerous import URLSafeTimedSerializer
from logger import logger
import time

# Load environment variables
load_dotenv()

# SMTP details
SMTP_SERVER = 'smtp.office365.com'
SMTP_PORT = 587
SMTP_USERNAME = os.getenv('SMTP_USERNAME')  # Your Microsoft 365 email address
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')  # Your Microsoft 365 email password
SENDER = 'customersupport@thebutchai.com'  # Your Microsoft 365 email address



# Generate a 6-digit OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Send OTP email
def send_otp_email(recipient_email, otp):
    SUBJECT = 'Your 2FA Code'
    BODY_TEXT = f"Your OTP for login is: {otp}. It is valid for 5 minutes."
    
    # Create the message container
    msg = MIMEMultipart()
    msg['Subject'] = SUBJECT
    msg['From'] = SENDER
    msg['To'] = recipient_email
    msg.attach(MIMEText(BODY_TEXT, 'plain'))
    
    try:
        # Set up the SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  # Secure the connection
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SENDER, recipient_email, msg.as_string())
        server.quit()
        logger.info(f"OTP sent to {recipient_email}")
    except Exception as e:
        logger.info(f"Error sending OTP: {e}")

# Store OTP for a recipient and set expiration time
def store_otp(recipient_email, otp):
    redis_key = f"otp:{recipient_email}"  # Create a unique key for each email
    expiration_time = 300 # OTP expires in 5 minutes (300 seconds)
    redis_client.setex(redis_key, expiration_time, otp)
    logger.info(f"Stored OTP for {recipient_email} in Redis, expires in 5 minutes.")

# Validate the OTP entered by the user
def validate_otp(recipient_email, otp_entered):
    redis_key = f"otp:{recipient_email}"

    # Retrieve OTP from Redis
    otp_stored = redis_client.get(redis_key)

    if otp_stored is None:
        logger.info(f"No OTP found for {recipient_email} or OTP expired.")
        return False, "No OTP sent or OTP expired"
    # Check if entered OTP matches the stored OTP
    if otp_stored.decode('utf-8') == otp_entered:
        # Delete the OTP from Redis after successful verification
        redis_client.delete(redis_key)
        return True, "OTP validated successfully"
    else:
        return False, "Invalid OTP"

# Generate a password reset token
def generate_password_reset_token(email):
    s = URLSafeTimedSerializer(os.getenv('FLASK_SECRET_KEY'))  # Use your Flask secret key
    token = s.dumps(email, salt=os.getenv('SECURITY_PASSWORD_SALT'))  # Use a security salt
    return token

# Verify the password reset token
def verify_password_reset_token(token, expiration=3600):
    s = URLSafeTimedSerializer(os.getenv('FLASK_SECRET_KEY'))
    try:
        email = s.loads(token, salt=os.getenv('SECURITY_PASSWORD_SALT'), max_age=expiration)
    except Exception as e:
        logger.info(f"Token verification error: {e}")
        return None
    return email

# Send a password reset email with a reset link
def send_password_reset_email(recipient_email, reset_link):
    SUBJECT = 'Password Reset Request'
    BODY_TEXT = f"Click the link to reset your password: {reset_link}. The link is valid for 1 hour."
    
    # Create the message container
    msg = MIMEMultipart()
    msg['Subject'] = SUBJECT
    msg['From'] = SENDER
    msg['To'] = recipient_email
    msg.attach(MIMEText(BODY_TEXT, 'plain'))
    
    try:
        # Set up the SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  # Secure the connection
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SENDER, recipient_email, msg.as_string())
        server.quit()
        logger.info(f"Password reset email sent to {recipient_email}")
    except Exception as e:
        logger.info(f"Error sending password reset email: {e}")

def send_email(recipient_email, subject, body_text):
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = SENDER
    msg['To'] = recipient_email
    msg.attach(MIMEText(body_text, 'plain'))

    try:
        # Set up the SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  # Secure the connection
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SENDER, recipient_email, msg.as_string())
        server.quit()
        logger.info(f"Email sent to {recipient_email}")
    except Exception as e:
        logger.info(f"Error sending email: {e}")
