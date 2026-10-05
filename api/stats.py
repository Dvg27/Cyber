import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, jsonify
from api._lib.database import get_connection

app = Flask(__name__)

@app.route('/api/stats')
def get_stats():
    conn = get_connection()
    c = conn.cursor()

    c.execute('SELECT COUNT(*) FROM scans')
    total = c.fetchone()[0]

    c.execute('SELECT COUNT(*) FROM scans WHERE score >= 70')
    threats = c.fetchone()[0]

    c.execute('SELECT COUNT(*) FROM scans WHERE score < 30')
    safe = c.fetchone()[0]

    c.execute('SELECT COUNT(DISTINCT value) FROM iocs')
    iocs = c.fetchone()[0]

    conn.close()

    return jsonify({
        'total': total,
        'threats': threats,
        'safe': safe,
        'iocs': iocs
    })

def handler(environ, start_response):
    return app(environ, start_response)
