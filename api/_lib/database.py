import sqlite3
import os

# On Vercel, /tmp is the only writable directory in serverless functions.
# Data resets on cold starts. For persistent storage, replace with a
# hosted database like PlanetScale, Supabase, or Railway.
DB_PATH = '/tmp/malware.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            size INTEGER,
            type TEXT,
            md5 TEXT,
            sha256 TEXT,
            score INTEGER,
            recommendation TEXT,
            static_details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            type TEXT,
            value TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    ''')

    conn.commit()
    conn.close()

def get_connection():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
