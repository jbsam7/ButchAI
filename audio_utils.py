import requests
import time
import re
import base64
import math
from elevenlabs.client import ElevenLabs
from anthropic import Anthropic
import os
from data_utils_gpt4o import get_db_connection,log_token_usage_and_cost_gpt4o
from data_utils import get_db_connection, log_token_usage_and_cost
import cv2


# Generate key frame phrases using GPT-4o
def generate_key_frame_phrases(combined_summary, custom_prompt, api_key, username, retries=3, delay=60):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    model = "gpt-4o-mini"  # specifically the model to use

    prompt = (
        f"--- Context ---\n{combined_summary}\n\n"
        f"--- Task ---\n"
        f"Pick 2 key frames you think help narrate the story from custom prompt: {custom_prompt}. "
        f"Generate just 1 phrase for each key frame. "
        f"Output must be exactly as so 'Frame (x): phrase, Frame (y): phrase', where x and y are the frame numbers you choose based on the content."
    )

    max_tokens = 100  # Assuming 100 tokens is sufficient for short phrases

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.8,
        "top_p": 1
    }

    for attempt in range(retries):
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)

        if response.status_code == 200:
            response_json = response.json()
            if 'choices' in response_json:
                key_frame_phrases = response_json['choices'][0]['message']['content']

                # Log token usage
                token_usage = response_json['usage']
                log_token_usage_and_cost(username, token_usage['prompt_tokens'], token_usage['completion_tokens'])

                return key_frame_phrases
        else:
            print(f"API Request failed with status code {response.status_code}: {response.text}")

            if attempt < retries - 1:
                time.sleep(delay)
            else:
                return "Error: API Request failed after retries."

# Extract phrases from the response
def extract_phrases(response_text):
    frame_phrases = {}
    matches = re.findall(r'Frame (\d+):\s*(.*?)(?= Frame \d+:|$)', response_text)
    for match in matches:
        frame_number = int(match[0])
        phrase = match[1].strip()
        frame_phrases[frame_number] = phrase
    return frame_phrases

def extract_frames(video_path, frame_interval):
    print(f"Starting frame extraction with interval: {frame_interval}")
    vidcap = cv2.VideoCapture(video_path)
    frames = []
    success, image = vidcap.read()
    count = 0
    while success:
        if count != 0 and count % frame_interval == 0:
            frames.append(image)
        success, image = vidcap.read()
        count += 1
    vidcap.release()
    print(f"Frame extraction complete. Total frames extracted: {len(frames)}")
    return frames

def encode_image(image):
    _, buffer = cv2.imencode('.jpg', image)
    encoded_image = base64.b64encode(buffer).decode('utf-8')
    return encoded_image

# Generate audio using ElevenLabs API
def generate_audio_from_text(prompt, voice_id):
    client = ElevenLabs(api_key=os.getenv("ELEVENLABS_API_KEY"))
    audio_generator = client.generate(text=prompt, voice=voice_id)
    # collect audio into bytes
    audio_data = b''.join(audio_generator) # Convert generator into bytes
    return audio_data

# Save audio to a file
def save_audio(audio, filename):
    with open(filename, 'wb') as f:
        f.write(audio)
    print(f"Audio saved to {filename}")

# Analyze the frame image using GPT-4o
def analyze_frame(image_data, api_key, username, retries=3, delay=60):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    prompt = f"What is in this image? Please describe in one sentence exactly."
    image_data_encoded = f"data:image/jpeg;base64,{image_data}"

    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": image_data_encoded}}
                ]
            }
        ],
        "max_tokens": 50
    }

    for attempt in range(retries):
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)

        if response.status_code == 200:
            response_json = response.json()
            if 'choices' in response_json:
                response_text = response_json['choices'][0]['message']['content']

                # Log token usage
                token_usage = response_json['usage']
                log_token_usage_and_cost(username, token_usage['prompt_tokens'], token_usage['completion_tokens'])

                return response_text
        else:
            print(f"API Request failed with status code {response.status_code}: {response.text}")

            if attempt < retries - 1:
                time.sleep(delay)
            else:
                return "Error: API Request failed."

# Calculate frame interval
def calculate_frame_interval(video_duration, fps, num_key_frames):
    # Calculate the total number of frames for the video
    total_frames = int(video_duration * fps)

    # Calculate the maximum allowed frame index for the last key frame
    max_frame_for_last_key = total_frames - (3 * fps)


    # Adjust total frames for key frame calculation by removing the buffer
    adjusted_total_frames = max_frame_for_last_key 

    # Calculate the frame interval for the desired number of key frames
    frame_interval = max(1, adjusted_total_frames // num_key_frames)

    return frame_interval, max_frame_for_last_key

# Generate a sequential summary from the combined frames
def generate_sequential_summary(combined_summary, api_key, username):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    prompt = (
        "--- Context ---\n"
        f"{combined_summary}\n\n"
        "--- Task ---\n"
        "In one concise sentence of no more than 15 words, summarize the key point from the above context."
    )

    max_tokens = 80

    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens
    }
    
    response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
    
    if response.status_code == 200:
        response_json = response.json()
        if 'choices' in response_json:
            sequential_summary = response_json['choices'][0]['message']['content']

            # Log token usage
            token_usage = response_json['usage']
            log_token_usage_and_cost(username, token_usage['prompt_tokens'], token_usage['completion_tokens'])

            return sequential_summary
        else:
            return "Error: Response did not contain expected 'choices' key."
    else:
        print("API Request failed with status code:", response.status_code)
        print("Response:", response.text)
        return "Error: API Request failed."

# Summarize the text using the mini model from chatgpt
def summarize_text(final_summary, word_limit, api_key, username, custom_prompt, custom_prompt_frame, key_frame_one, key_frame_two, key_frame_one_time, key_frame_two_time, video_duration, retries=3, delay=60):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    key_one_ratio = key_frame_one_time / video_duration
    key_two_ratio = key_frame_two_time / video_duration

    key_one_words = int(word_limit * key_one_ratio)
    key_two_words = int(word_limit * key_two_ratio)
    remaining_words = word_limit - (key_one_words + key_two_words)
    remaining_words = max(remaining_words, 0)

    prompt = (
        f"--- Context ---\n{final_summary}\n\n--- Task ---\n"
        f"Create a concise, {word_limit}-word narrative script focused on {custom_prompt_frame}. "
        f"Ensure the narrative reflects the mood and elements of the context, "
        f"ends with a strong conclusion, contains no symbols, brackets, or phrases like 'narration:'. "
        f"Include the phrase '{key_frame_one}' within the range of {key_one_words-5}-{key_one_words+5} words and phrase '{key_frame_two}' within the range of {key_two_words-5}-{key_two_words+5} words. "
        f"{custom_prompt}"
    )

    max_tokens = math.ceil(word_limit * 1.33) + 150

    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens
    }

    for attempt in range(retries):
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)

        if response.status_code == 200:
            response_json = response.json()
            if 'choices' in response_json:
                summary_text = response_json['choices'][0]['message']['content']

                # Lot token usage 
                token_usage = response_json['usage']
                log_token_usage_and_cost(username, token_usage['prompt_tokens'], token_usage['completion_tokens'])

                return summary_text
        else: 
            print(f"API Request failed with status code {response.status_code}: {response.text}")
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                return "Error: API Request failed after retries."