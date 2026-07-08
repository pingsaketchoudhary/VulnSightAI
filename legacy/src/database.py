# src/database.py

import sqlite3
import json
import os
from datetime import datetime

# Define the path for the database file in the project's root directory
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'vulnsight.db')

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row # This allows accessing columns by name
    return conn

def init_db():
    """
    Initializes the database and creates the 'scans' table if it doesn't exist.
    """
    print("[+] Initializing database...")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            scan_data TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("[+] Database initialized successfully.")

def save_scan_result(scan_data):
    """
    Saves a completed scan result to the database.
    The scan_data dictionary is stored as a JSON string.
    """
    print("[+] Saving scan result to database...")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    target = scan_data.get('target')
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Convert the entire results dictionary to a JSON string for storage
    scan_data_json = json.dumps(scan_data)
    
    cursor.execute(
        "INSERT INTO scans (target, timestamp, scan_data) VALUES (?, ?, ?)",
        (target, timestamp, scan_data_json)
    )
    conn.commit()
    conn.close()
    print("[+] Scan result saved.")

def get_scan_history():
    """
    Retrieves a list of all past scans (id, target, timestamp) from the database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, target, timestamp FROM scans ORDER BY timestamp DESC")
    history = cursor.fetchall()
    conn.close()
    return history

def get_scan_by_id(scan_id):
    """
    Retrieves the full data for a specific scan by its ID.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT scan_data FROM scans WHERE id = ?", (scan_id,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        # Parse the JSON string back into a Python dictionary
        return json.loads(result['scan_data'])
    return None

