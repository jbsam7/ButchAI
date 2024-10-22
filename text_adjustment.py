import random
import math
import re
from logger import logger

def calculate_word_count(target_duration, words_per_minute=150):
    # Calculate the expected word count based on target duration
    return math.ceil((target_duration / 60) * words_per_minute)

def add_pauses_to_text(text, target_word_count):
    # Add pauses to the text (...) to increase narration

    sentences = re.split(r'([,.!?])', text)  # Split by punctuation, retaining the punctuation
    current_word_count = len(text.split())

    if current_word_count >= target_word_count:
        return text
    
    additional_words_needed = target_word_count - current_word_count

    # Find positions of commas first
    comma_boundaries = [i for i, s in enumerate(sentences) if s.strip() == ',']
    other_boundaries = [i for i, s in enumerate(sentences) if s.strip() in {'.', '!', '?'}]

    # If there aren't enough commas, add sentence-ending punctuation as fallback
    all_boundaries = comma_boundaries + other_boundaries

    # If there are too few commas or boundaries, we use the whole sentence array
    if len(comma_boundaries) < additional_words_needed:
        pause_positions = random.sample(all_boundaries, min(additional_words_needed, len(all_boundaries)))
    else:
        pause_positions = random.sample(comma_boundaries, additional_words_needed)

    # Insert pauses at the selected positions
    for position in sorted(pause_positions, reverse=True):
        sentences.insert(position + 1, '...')

    adjusted_text = ''.join(sentences)
    
    # Ensure final text meets the word count requirement
    adjusted_word_count = len(adjusted_text.split())
    
    if adjusted_word_count < target_word_count:
        # If we're still short on words, append additional pauses at the end
        adjusted_text += ' ...' * (target_word_count - adjusted_word_count)

    return adjusted_text

def adjust_text_for_duration(text, target_duration, words_per_minute=150):
    # Adjust the input text by adding pauses to match the desired narration length
    target_word_count = calculate_word_count(target_duration, words_per_minute)
    logger.info(f"Target word count needed: {target_word_count}")
    logger.info(f'Original text word count: {len(text.split())}')

    adjusted_text = add_pauses_to_text(text, target_word_count)
    logger.info(f"Adjusted text word count: {len(adjusted_text.split())}")
    
    return adjusted_text
