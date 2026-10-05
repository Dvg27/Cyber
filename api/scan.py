import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from api._lib.database import get_connection
from api._lib.analyzer import analyze_file

app = Flask(__name__)

@app.route('/api/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    filename = secure_filename(file.filename)
    file_bytes = file.read()

    report = analyze_file(filename, file_bytes)

    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO scans (filename, size, type, md5, sha256, score, recommendation, static_details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        report['filename'], report['size'], report['type'],
        report['md5'], report['sha256'], report['score'],
        report['recommendation'], json.dumps(report['static_details'])
    ))
    scan_id = c.lastrowid

    for ioc in report['iocs']:
        c.execute('''
            INSERT INTO iocs (scan_id, type, value)
            VALUES (?, ?, ?)
        ''', (scan_id, ioc['type'], ioc['value']))

    conn.commit()
    conn.close()

    return jsonify({'id': scan_id, 'message': 'Scan complete'})

# Vercel handler
def handler(request, context=None):
    return app(request.environ, lambda *args: None)
