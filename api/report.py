import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
from flask import Flask, jsonify, request
from api._lib.database import get_connection

app = Flask(__name__)

@app.route('/api/report/<int:report_id>')
def get_report(report_id):
    conn = get_connection()
    try:
        c = conn.cursor()

        c.execute('SELECT * FROM scans WHERE id = ?', (report_id,))
        scan = c.fetchone()

        if not scan:
            return jsonify({'error': 'Report not found'}), 404

        c.execute('SELECT type, value FROM iocs WHERE scan_id = ?', (report_id,))
        iocs = c.fetchall()
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

    result = dict(scan)
    # Safely parse static_details JSON, fallback to empty list on invalid JSON
    try:
        result['static_details'] = json.loads(result['static_details']) if result['static_details'] else []
    except (json.JSONDecodeError, TypeError):
        result['static_details'] = []
    result['iocs'] = [dict(ioc) for ioc in iocs]

    return jsonify(result)

# Vercel serverless WSGI handler
def handler(environ, start_response):
    return app.wsgi_app(environ, start_response)
