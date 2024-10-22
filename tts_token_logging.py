import sqlite3
from logger import logger

# --- Authentication Logic ---

def get_db_connection():
    conn = sqlite3.connect('users.db')
    return conn

# Function to count characters
def count_characters(text):
    return len(text)

# Function to calculate costs based on character usage
def calculate_tts_cost(character_count, rate_per_million=30.000):
    cost = (character_count / 1_000_000) * rate_per_million
    return cost

# Function to log TTS character usage and cost
def log_tts_usage_and_cost(username, character_count, rate_per_million=30.000):
    # Calculate the cost for this transaction
    total_cost = calculate_tts_cost(character_count, rate_per_million)

    #Update total cost in database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users
        SET tts_characters = tts_characters + ?, total_cost_tts = total_cost_tts + ?
        WHERE username = ?''', (character_count, total_cost, username))
    
    # Commit the changes and close the connection
    conn.commit()
    conn.close()

    # Output logging information
    logger.info(f"Username: {username}")
    logger.info(f"Characters used: {character_count}")
    logger.info(f"Total cost: ${total_cost:.8f} USD")

