import sqlite3

# --- Authentication Logic ---
def get_db_connection():
    conn = sqlite3.connect('users.db')
    return conn

# Update token w/ usage
def update_user_token_usage(username, input_tokens, output_tokens):
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

# Function to calculate costs based on actual token usage
def calculate_cost(input_tokens, output_tokens, input_token_rate=0.150, output_token_rate=0.600):
    input_cost = (input_tokens / 1_000_000) * input_token_rate
    output_cost = (output_tokens / 1_000_000) * output_token_rate
    total_cost = input_cost + output_cost
    return total_cost

# Function to log token usage and costs
def log_token_usage_and_cost(username, input_tokens, output_tokens):
    # Calculate the cost for this transaction.
    total_cost = calculate_cost(input_tokens, output_tokens)


    # Update the users token usage and duration
    update_user_token_usage(username, input_tokens, output_tokens)

    # Update the user's total cost in the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users
        SET total_cost = total_cost + ?
        WHERE username = ?''',
        (total_cost, username))
    
    # Commit the changes to close the connection
    conn.commit()
    conn.close()

    print(f"Username: {username}")
    print(f"Input tokens: {input_tokens}")
    print(f"Output tokens: {output_tokens}")
    print(f"Total cost: ${total_cost:.8f} USD")