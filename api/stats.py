import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, jsonify
from api._lib.database import get_connection

app = Flask(__name__)

@app.route('/api/stats')
def get_stats():
    conn = get_connection()
    try:
        c = conn.cursor()

        c.execute('SELECT COUNT(*) FROM scans')
        total = c.fetchone()[0]

        c.execute('SELECT COUNT(*) FROM scans WHERE score >= 70')
        threats = c.fetchone()[0]

        c.execute('SELECT COUNT(*) FROM scans WHERE score < 30')
        safe = c.fetchone()[0]

        c.execute('SELECT COUNT(DISTINCT value) FROM iocs')
        iocs = c.fetchone()[0]
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

    return jsonify({
        'total': total,
        'threats': threats,
        'safe': safe,
        'iocs': iocs
    })

# Vercel serverless WSGI handler
def handler(environ, start_response):
    return app.wsgi_app(environ, start_response)
