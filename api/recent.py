import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, jsonify
from api._lib.database import get_connection

app = Flask(__name__)

@app.route('/api/recent')
def get_recent_scans():
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute('SELECT id, filename, sha256, score, timestamp FROM scans ORDER BY timestamp DESC LIMIT 10')
        scans = c.fetchall()
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()
    return jsonify([dict(scan) for scan in scans])

# Vercel serverless WSGI handler
def handler(environ, start_response):
    return app.wsgi_app(environ, start_response)
