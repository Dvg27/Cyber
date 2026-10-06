from flask import Flask, request, jsonify
import os
import json
from werkzeug.utils import secure_filename
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
    report = analyze_file(filename, file_bytes)
    
    # Save to database
    conn = get_connection()
    try:
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

    return jsonify({'id': scan_id, 'message': 'Scan complete'})

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
    result['static_details'] = json.loads(result['static_details']) if result['static_details'] else []
    result['iocs'] = [dict(ioc) for ioc in iocs]
    
    return jsonify(result)

@app.route('/api/recent')
def get_recent_scans():
    conn = get_connection()
    c = conn.cursor()
    c.execute('SELECT id, filename, sha256, score, timestamp FROM scans ORDER BY timestamp DESC LIMIT 10')
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)
