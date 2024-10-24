import sqlite3
from logger import logger

# --- Authentication Logic ---
def get_db_connection():
    conn = sqlite3.connect('users.db')
    return conn

# Update token w/ usage for GPT-4o
def update_user_token_usage_gpt4o(username, input_tokens, output_tokens):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users
        SET input_tokens = input_tokens + ?,
            output_tokens = output_tokens + ?     
        WHERE username = ?''',
        (input_tokens, output_tokens, username))
    conn.commit()
    conn.close()

# Function to calculate costs based on actual token usage for GPT-4o
def calculate_cost_gpt4o(input_tokens, output_tokens, input_token_rate=5.00, output_token_rate=15.00):
    input_cost = (input_tokens / 1_000_000) * input_token_rate
    output_cost = (output_tokens / 1_000_000) * output_token_rate
    total_cost = input_cost + output_cost
    return total_cost

# Function to log token usage and costs for GPT-4o
def log_token_usage_and_cost_gpt4o(username, input_tokens, output_tokens, video_duration_increment):
    # Calculate the cost for this transaction
    total_cost = calculate_cost_gpt4o(input_tokens, output_tokens)


    # Update the users token usage and duration
    update_user_token_usage_gpt4o(username, input_tokens, output_tokens)

    # Update the users total cost in the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users
        SET total_cost_gpt4o = total_cost_gpt4o + ?,
            video_duration = video_duration + ?
        WHERE username = ?''',
        (total_cost, video_duration_increment, username))
    
    # Commit the changes to close the connection
    conn.commit()

    # Verify the database saved successfully
    cursor.execute('SELECT video_duration FROM users WHERE username = ?', (username,))
    updated_video_duration = cursor.fetchone()[0]
    logger.info(f"Updated video duration in DB for {username}: {updated_video_duration} seconds")
    conn.close()

    logger.info(f"Username: {username}")
    logger.info(f"Input tokens: {input_tokens}")
    logger.info(f"Output tokens: {output_tokens}")
    logger.info(f"Video duration: {video_duration_increment} seconds")
    logger.info(f"Total cost: ${total_cost:.4f} USD")
    



