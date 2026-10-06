import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, jsonify
from api._lib.database import get_connection

app = Flask(__name__)

@app.route('/api/iocs')
def get_all_iocs():
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute('''
            SELECT i.type, i.value, i.timestamp, s.filename as source_file
            FROM iocs i
            LEFT JOIN scans s ON i.scan_id = s.id
            ORDER BY i.timestamp DESC
            LIMIT 50
        ''')
        iocs = c.fetchall()
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()
    return jsonify([dict(ioc) for ioc in iocs])

# Vercel serverless WSGI handler
def handler(environ, start_response):
    return app.wsgi_app(environ, start_response)
