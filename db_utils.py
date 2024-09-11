import sqlite3
import hashlib
from data_utils import get_db_connection

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        REMOVED_hash TEXT NOT NULL,
        subscription_status TEXT DEFAULT 'inactive',
        first_name TEXT,
        last_name TEXT,
        dob TEXT,
        email TEXT,
        role TEXT DEFAULT 'users',
        input_tokens INTEGER DEFAULT 0,
        output_tokens INTEGER DEFAULT 0,
        video_duration REAL DEFAULT 0.0,
        tts_characters INTEGER DEFAULT 0,
        total_cost REAL DEFAULT 0.0,
        total_cost_gpt4o REAL DEFAULT 0.0,
        total_cost_tts REAL DEFAULT 0.0,
        tier TEXT DEFAULT 'basic',
        subscription_id TEXT 
    )
    ''')
    conn.commit()
    conn.close()

def update_db_schema():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch existing column names
    cursor.execute("PRAGMA table_info(users)")
    existing_columns = [column[1] for column in cursor.fetchall()]

    # Add columns if they don't exist already 
    if 'first_name' not in existing_columns:
        cursor.execute('ALTER TABLE users ADD COLUMN first_name TEXT')

    conn.commit()
    conn.close()

def hash_REMOVED(REMOVED):
    return hashlib.sha256(REMOVED.encode()).hexdigest()


