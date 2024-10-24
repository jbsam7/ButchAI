import requests
import time
import cv2
import base64
import math
import os
from data_utils import log_token_usage_and_cost
from elevenlabs.client import ElevenLabs
from logger import logger

# Extract fewer frames (2 per minute, 1 per 30 seconds)
def extract_basic_frames(video_path, video_duration):
    # Determine frame interval based on duration
    num_frames = 2 if video_duration > 30 else 1
    vidcap = cv2.VideoCapture(video_path)
    frames = []
    
    # Total frames in video
    total_frames = int(vidcap.get(cv2.CAP_PROP_FRAME_COUNT))
    
    # Calculate interval between frames
    frame_interval = max(1, total_frames // num_frames)

    success, image = vidcap.read()
    count = 0
    while success:
        if count % frame_interval == 0:
            frames.append(image)
            logger.info(f"Extracting frame {count} for analysis.")
        success, image = vidcap.read()
        count += 1

    vidcap.release()
    logger.info(f"Extracted {len(frames)} frames for basic analysis.")
    return frames

# Encode the image for analysis
def encode_image(image):
    _, buffer = cv2.imencode('.jpg', image)
    encoded_image = base64.b64encode(buffer).decode('utf-8')
    return encoded_image

def analyze_frame_basic(encoded_image, api_key, username, retries=3, delay=60):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    # Prepare the prompt with the image included as base64
    prompt = "What is in this image? Please describe it in one sentence exactly."
    image_data_encoded = f"data:image/jpeg;base64,{encoded_image}"

    # Structure the payload to include both text and image in the request
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
        "max_tokens": 50,
        "temperature": 0.8
    }

    for attempt in range(retries):
        logger.info(f"Sending frame for analysis (attempt {attempt + 1})...")  # Print statement for frame analysis attempt
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)

        if response.status_code == 200:
            response_json = response.json()
            if 'choices' in response_json:
                result_text = response_json['choices'][0]['message']['content']
                logger.info(f"Frame analysis result: {result_text}") # Print result from image analysis

                # Log token usage for cost tracking
                token_usage = response_json['usage']
                log_token_usage_and_cost(username, token_usage['prompt_tokens'], token_usage['completion_tokens'])

                return result_text
        else:
            logger.info(f"Frame analysis failed: {response.status_code}, {response.text}")
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                return "Error analyzing frame after retries."


# Generate a sequential summary for basic users (without key frame phrases)
def generate_basic_summary(combined_summary, api_key, username):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    
    prompt = (
        "--- Context ---\n"
        f"{combined_summary}\n\n"
        "--- Task ---\n"
        "Summarize the main points in 1 concise sentence."
    )

    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 100,
        "temperature": 0.8
    }

    response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)

    if response.status_code == 200:
        response_json = response.json()
        summary = response_json['choices'][0]['message']['content']

        # Log token usage for cost tracking
        token_usage = response_json['usage']
        log_token_usage_and_cost(username, token_usage['prompt_tokens'], token_usage['completion_tokens'])

        return summary
    else:
        logger.info(f"Summary generation failed: {response.status_code}")
        return "Error generating summary"
    
# Summarize text using GPT Mini
def summarize_text_basic(final_summary, word_limit, api_key, custom_prompt, username, retries=3, delay=60):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    prompt = (
        f"--- Context ---\n{final_summary}\n\n"
        f"--- Task ---\n"
        f"Create a concise, {word_limit}-word narrative based on the above context, focusing on {custom_prompt}."
        "Ensure the narrative reflects the main points, ends with a strong conclusion, and contains no symbols or unnecessary phrases"
    )

    max_tokens = math.ceil(word_limit * 1.33) + 150

    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens, 
        "temperature": 0.8
    }

    for attempt in range(retries):
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)

        if response.status_code == 200:
            response_json = response.json()
            if 'choices' in response_json:
                final_summary_text = response_json['choices'][0]['message']['content']

                # Log token usage for cost tracking
                token_usage = response_json['usage']
                log_token_usage_and_cost(username, token_usage['prompt_tokens'], token_usage['completion_tokens'])

                return final_summary_text
        else:
            logger.info(f"API Request failed with status code {response.status_code}: {response.text}")

            if attempt < retries - 1:
                time.sleep(delay)
            else:
                return "Error: API Request failed after retries"

# Main function to summarize video for basic users
def summarize_video_basic(video_path, api_key, username, custom_prompt):
    logger.info("Starting basic video summarization...")

    # Capture video details
    vidcap = cv2.VideoCapture(video_path)
    fps = vidcap.get(cv2.CAP_PROP_FPS)
    frame_count = int(vidcap.get(cv2.CAP_PROP_FRAME_COUNT))
    video_duration = frame_count / fps
    vidcap.release()

    logger.info(f"Video duration: {video_duration} seconds")

    # Extract frames based on video duration
    frames = extract_basic_frames(video_path, video_duration)

    # Analyze each frame
    summaries = []
    for i, frame in enumerate(frames):
        logger.info(f"Analyzing frame {i + 1}/{len(frames)}")
        encoded_image = encode_image(frame)
        analysis_result = analyze_frame_basic(encoded_image, api_key, username)
        logger.info(f"Frame {i + 1} analysis result: {analysis_result}")
        summaries.append(analysis_result)

    combined_summary = " ".join(summaries)
    logger.info(f"Combined summary of all frames: {combined_summary}")  # Print combined summary of frames

    # Generate sequential summary
    sequential_summary = generate_basic_summary(combined_summary, api_key, username)

    # Determine the target word count based on video duration
    words_per_minute = 140
    word_limit = math.ceil((video_duration / 60) * words_per_minute)

    # Generate the final summary using the custom prompt and sequential summary
    final_summary = summarize_text_basic(sequential_summary, word_limit, api_key, custom_prompt, username)

    logger.info(f"Generated summary: {final_summary}")
    return final_summary
