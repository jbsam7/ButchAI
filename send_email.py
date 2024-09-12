import random
from datetime import datetime, timedelta
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# SMTP details
SMTP_SERVER = 'smtp.office365.com'
SMTP_PORT = 587
SMTP_USERNAME = os.getenv('SMTP_USERNAME')  # Your Microsoft 365 email address
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')  # Your Microsoft 365 email REMOVED
SENDER = 'REMOVED'  # Your Microsoft 365 email address

# Temporary OTP storage (for production, consider using a database or Redis)
otp_storage = {}

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
        print(f"OTP sent to {recipient_email}")
    except Exception as e:
        print(f"Error sending OTP: {e}")

# Store OTP for a recipient and set expiration time
def store_otp(recipient_email, otp):
    expiration_time = datetime.now() + timedelta(minutes=5)  # OTP expires in 5 minutes
    otp_storage[recipient_email] = {'otp': otp, 'expires_at': expiration_time}

# Validate the OTP entered by the user
def validate_otp(recipient_email, otp_entered):
    otp_info = otp_storage.get(recipient_email)
    if not otp_info:
        return False, "No OTP sent or OTP expired"
    
    if datetime.now() > otp_info['expires_at']:
        otp_storage.pop(recipient_email)  # Remove expired OTP
        return False, "OTP expired"
    
    if otp_info['otp'] == otp_entered:
        otp_storage.pop(recipient_email)  # Remove OTP after successful validation
        return True, "OTP validated successfully"
    
    return False, "Invalid OTP"
