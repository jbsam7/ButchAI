# tts_audio.py
from pathlib import Path
from openai import OpenAI
from logger import logger
from dotenv import load_dotenv
import os
import boto3
import time

load_dotenv()

# Initialize DigitalOcean Spaces client
s3_client = boto3.client(
    's3',
    endpoint_url=os.getenv("DO_SPACES_ENDPOINT"),
    aws_access_key_id=os.getenv("DO_SPACES_KEY"),
    aws_secret_access_key=os.getenv("DO_SPACES_SECRET")
)

SPACE_NAME = os.getenv("DO_SPACES_NAME")

def generate_audio_with_openai(input_text, voice="fable"):
    """
    Generate TTS audio from input text using OpenAI API and save the audio to a file.
    
    Args:
    - input_text: The text to convert to speech.
    - voice: The voice model to use (default is 'alloy').

    Returns:
    - speech_file_path: Path to the generated audio file.
    """
    client = OpenAI(api_key=os.getenv("GPT_API_KEY"))  # Initialize the OpenAI client with API key

    
    # Call the OpenAI TTS API to generate speech
    response = client.audio.speech.create(
        model="tts-1-hd",
        voice=voice,  # Choose a voice
        input=input_text  # The text to convert to speech
    )

    # Define a unique file key
    file_key = f"audio/speech_openai_{int(time.time())}.mp3"
    
    # Upload the file to DigitalOcean Space
    s3_client.put_object(
        Bucket=SPACE_NAME,
        Key=file_key,
        Body=response.content,
        ContentType='audio/mpeg'
    )

    # Generate a signed URL with a specific expiration time (e.g., 1 hour)
    audio_url = s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': SPACE_NAME, 'Key': file_key},
        ExpiresIn=3600  # Link expires in 1 hour (3600 seconds)
    )

    return audio_url