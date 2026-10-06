import sqlite3
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if os.environ.get('MALWARE_DB_PATH'):
    DB_PATH = os.environ['MALWARE_DB_PATH']
elif os.environ.get('VERCEL'):
    DB_PATH = '/tmp/malware.db'
else:
    DB_PATH = os.path.join(PROJECT_ROOT, 'database', 'malware.db')

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
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
    """Get a database connection, ensuring tables are initialized first."""
    init_db()
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn
