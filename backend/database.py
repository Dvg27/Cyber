import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'malware.db')
DB_PATH = os.environ.get('MALWARE_DB_PATH', DB_PATH)

def init_db():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
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
            malware_type TEXT DEFAULT 'Clean / Benign',
            malware_family TEXT DEFAULT 'None',
            matched_rules TEXT DEFAULT '[]',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Auto-migrate existing database columns if upgrading
    existing_cols = [row[1] for row in c.execute("PRAGMA table_info(scans)").fetchall()]
    if 'malware_type' not in existing_cols:
        c.execute("ALTER TABLE scans ADD COLUMN malware_type TEXT DEFAULT 'Clean / Benign'")
    if 'malware_family' not in existing_cols:
        c.execute("ALTER TABLE scans ADD COLUMN malware_family TEXT DEFAULT 'None'")
    if 'matched_rules' not in existing_cols:
        c.execute("ALTER TABLE scans ADD COLUMN matched_rules TEXT DEFAULT '[]'")
    
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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

