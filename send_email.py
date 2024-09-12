import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load the environment from the .env file
load_dotenv()

# SMTP details
SMTP_SERVER = 'smtp.office365.com'
SMTP_PORT = 587
SMTP_USERNAME = os.getenv('SMTP_USERNAME')  # Your Microsoft 365 email address
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')  # Your Microsoft 365 email REMOVED

# Email details
SENDER = 'REMOVED'  # Your Microsoft 365 email address
RECIPIENT = 'justinsamuelson7@gmail.com'  # The recipient's email address
SUBJECT = 'Test Email via Microsoft 365 SMTP'
BODY_TEXT = "This is a test email sent through Microsoft 365 SMTP."

# Create the message container
msg = MIMEMultipart()
msg['Subject'] = SUBJECT
msg['From'] = SENDER
msg['To'] = RECIPIENT

# Attach the body text
msg.attach(MIMEText(BODY_TEXT, 'plain'))

# Send the email
try:
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()  # Secure the connection
    server.login(SMTP_USERNAME, SMTP_PASSWORD)
    server.sendmail(SENDER, RECIPIENT, msg.as_string())
    server.quit()
    print("Email sent successfully!")
except Exception as e:
    print(f"Error sending email: {e}")
