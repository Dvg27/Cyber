from flask import Flask, request, jsonify
import os
import json
from werkzeug.utils import secure_filename
try:
    from .database import init_db, get_connection
    from .analyzer import analyze_file
except ImportError:
    from database import init_db, get_connection
    from analyzer import analyze_file

app = Flask(__name__, static_folder='../frontend', static_url_path='/')

# Ensure database is initialized
init_db()

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/<path:path>')
def serve_html(path):
    if not path.endswith('.html') and not path.endswith('.css') and not path.endswith('.js') and '.' not in path:
        path += '.html'
    return app.send_static_file(path)

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
    # Run analysis
    report = analyze_file(filename, file_bytes)
    
    # Save to database
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

        # Save IoCs
        for ioc in report['iocs']:
            c.execute('''
                INSERT INTO iocs (scan_id, type, value)
                VALUES (?, ?, ?)
            ''', (scan_id, ioc['type'], ioc['value']))

        conn.commit()
    except Exception as e:
        conn.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

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
            'timestamp': None
        }
    })

@app.route('/api/report/<int:report_id>')
def get_report(report_id):
    conn = get_connection()
    c = conn.cursor()
    
    c.execute('SELECT * FROM scans WHERE id = ?', (report_id,))
    scan = c.fetchone()
    
    if not scan:
        return jsonify({'error': 'Report not found'}), 404
        
    c.execute('SELECT type, value FROM iocs WHERE scan_id = ?', (report_id,))
    iocs = c.fetchall()
    
    conn.close()
    
    result = dict(scan)
    try:
        result['static_details'] = json.loads(result['static_details']) if result['static_details'] else []
    except Exception:
        result['static_details'] = []

    try:
        result['matched_rules'] = json.loads(result['matched_rules']) if result.get('matched_rules') else []
    except Exception:
        result['matched_rules'] = []

    result['iocs'] = [dict(ioc) for ioc in iocs]
    
    return jsonify(result)

@app.route('/api/recent')
def get_recent_scans():
    conn = get_connection()
    c = conn.cursor()
    c.execute('SELECT id, filename, sha256, score, malware_type, malware_family, timestamp FROM scans ORDER BY timestamp DESC LIMIT 10')
    scans = c.fetchall()
    conn.close()
    return jsonify([dict(scan) for scan in scans])

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

@app.route('/api/iocs')
def get_all_iocs():
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        SELECT i.type, i.value, i.timestamp, s.filename as source_file
        FROM iocs i
        LEFT JOIN scans s ON i.scan_id = s.id
        ORDER BY i.timestamp DESC
        LIMIT 50
    ''')
    iocs = c.fetchall()
    conn.close()
    return jsonify([dict(ioc) for ioc in iocs])

@app.route('/api/samples', methods=['GET'])
def list_samples():
    """Returns the catalog of safe educational sample test files."""
    samples_dir = os.path.join(os.path.dirname(__file__), '..', 'samples')
    if not os.path.exists(samples_dir):
        return jsonify([])
    
    catalog = [
        {
            "id": "eicar",
            "filename": "01_eicar_test_sample.txt",
            "category": "EICAR Antivirus Standard",
            "expected_type": "EICAR Standard Test File",
            "threat_level": "CRITICAL / TEST (Score: 100)",
            "description": "Standard benign anti-virus test file recognized worldwide by all security engines to verify static detection pipelines safely."
        },
        {
            "id": "ransomware",
            "filename": "02_ransomware_simulation_sample.txt",
            "category": "Ransomware Simulation",
            "expected_type": "Ransomware",
            "threat_level": "CRITICAL (Score: 85-95)",
            "description": "Safe simulated text sample demonstrating shadow copy deletion commands, ransom note extortion phrasings, and crypto APIs."
        },
        {
            "id": "infostealer",
            "filename": "03_infostealer_simulation_sample.txt",
            "category": "Spyware / InfoStealer",
            "expected_type": "Spyware / InfoStealer",
            "threat_level": "HIGH (Score: 80-90)",
            "description": "Safe simulated text sample demonstrating browser password database targets, DPAPI extraction APIs, and crypto wallet paths."
        },
        {
            "id": "trojan",
            "filename": "04_trojan_dropper_simulation_sample.txt",
            "category": "Trojan / Dropper Simulation",
            "expected_type": "Trojan / Dropper",
            "threat_level": "HIGH (Score: 80-90)",
            "description": "Safe simulated text sample with process memory injection markers (VirtualAllocEx) and payload download commands."
        },
        {
            "id": "keylogger",
            "filename": "05_keylogger_simulation_sample.txt",
            "category": "Keylogger Simulation",
            "expected_type": "Keylogger",
            "threat_level": "HIGH (Score: 75-85)",
            "description": "Safe simulated text sample demonstrating keyboard hook APIs (SetWindowsHookEx) and keystroke polling mechanisms."
        },
        {
            "id": "clean",
            "filename": "06_clean_document_sample.txt",
            "category": "Benign Clean Document",
            "expected_type": "Clean / Benign",
            "threat_level": "SAFE / CLEAN (Score: 0)",
            "description": "Completely benign text file with ordinary corporate notes and documentation containing zero threat indicators."
        }
    ]
    return jsonify(catalog)

@app.route('/api/samples/<filename>')
def download_sample(filename):
    """Allows downloading safe benign sample files for scanner validation."""
    samples_dir = os.path.join(os.path.dirname(__file__), '..', 'samples')
    safe_name = secure_filename(filename)
    file_path = os.path.join(samples_dir, safe_name)
    if not os.path.exists(file_path):
        return jsonify({'error': 'Sample not found'}), 404
    
    with open(file_path, 'rb') as f:
        data = f.read()
    from flask import Response
    return Response(
        data,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment;filename={safe_name}"}
    )


if __name__ == '__main__':
    app.run(debug=True, port=5000)
