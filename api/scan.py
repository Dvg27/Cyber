import sys
import os
# Ensure the project root is always on sys.path for Vercel serverless execution
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

    # Run analysis
    report = analyze_file(filename, file_bytes)

    try:
        conn = get_connection()
        try:
            c = conn.cursor()
            c.execute('''
                INSERT INTO scans (filename, size, type, md5, sha256, score, recommendation, static_details, malware_type, malware_family, matched_rules)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report['filename'], report['size'], report['type'],
                report['md5'], report['sha256'], report['score'],
                report['recommendation'], json.dumps(report['static_details']),
                report.get('malware_type', 'Clean / Benign'),
                report.get('malware_family', 'None'),
                json.dumps(report.get('matched_rules', []))
            ))
            scan_id = c.lastrowid

            for ioc in report['iocs']:
                c.execute('''
                    INSERT INTO iocs (scan_id, type, value)
                    VALUES (?, ?, ?)
                ''', (scan_id, ioc['type'], ioc['value']))

            conn.commit()
        except Exception as db_err:
            conn.rollback()
            return jsonify({'error': f'Database error: {db_err}'}), 500
        finally:
            conn.close()
    except Exception as db_err:
        return jsonify({'error': f'Database error: {db_err}'}), 500

    # Return full report data including classification
    return jsonify({
        'id': scan_id,
        'message': 'Scan complete',
        'report': {
            'id': scan_id,
            'filename': report['filename'],
            'size': report['size'],
            'type': report['type'],
            'md5': report['md5'],
            'sha256': report['sha256'],
            'score': report['score'],
            'malware_type': report.get('malware_type', 'Clean / Benign'),
            'malware_family': report.get('malware_family', 'None'),
            'severity': report.get('severity', 'LOW'),
            'matched_rules': report.get('matched_rules', []),
            'recommendation': report['recommendation'],
            'static_details': report['static_details'],
            'iocs': report['iocs'],
            'timestamp': None  # will be set client-side
        }
    })

# Vercel serverless WSGI handler
def handler(environ, start_response):
    return app.wsgi_app(environ, start_response)
