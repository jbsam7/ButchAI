# tts_audio.py
from pathlib import Path
from openai import OpenAI
import os

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

    # Define the path to save the audio file
    speech_file_path = Path(__file__).parent / "speech_openai.mp3"
    
    # Call the OpenAI TTS API to generate speech
    response = client.audio.speech.create(
        model="tts-1",
        voice=voice,  # Choose a voice
        input=input_text  # The text to convert to speech
    )
    
    # Assuming `response` contains the raw audio content
    # Write the audio data to a file manually
    with open(speech_file_path, "wb") as audio_file:
        audio_file.write(response.content)

    return str(speech_file_path)  # Return the file path as a string for further processing
