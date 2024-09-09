from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3

app = Flask(__name__)
CORS(app)

# Initialize the database
def init_db():
    conn = sqlite3.connect('activity_logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_name TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            url TEXT NOT NULL,
            action TEXT,
            message TEXT  
        )
    ''')
    conn.commit()
    conn.close()

# Function to determine the action type based on the URL
def get_action_from_url(url):
    if 'backend-api' in url:
        return 'Backend API Call'
    elif 'public-api' in url:
        return 'Public API Call'
    elif 'ces/v1' in url:
        return 'CES API Call'
    elif url.endswith('.js'):
        return 'JavaScript File Request'
    elif url.endswith('favicon.ico'):
        return 'Favicon Request'
    elif url == 'https://chatgpt.com/':
        return 'Page Visit'
    return 'Unknown Action'

@app.route('/admin')
def admin_page():
    return render_template('admin.html')

# API to fetch logs for a specific student
@app.route('/api/logs/<student_name>', methods=['GET'])
def get_logs_by_student(student_name):
    conn = sqlite3.connect('activity_logs.db')
    cursor = conn.cursor()

    # Fetch all logs and the request count for the given student
    cursor.execute('SELECT * FROM logs WHERE student_name = ?', (student_name,))
    logs = cursor.fetchall()

    cursor.execute('SELECT COUNT(*) FROM logs WHERE student_name = ?', (student_name,))
    request_count = cursor.fetchone()[0]
    
    conn.close()

    log_list = []
    for log in logs:
        log_list.append({
            'student_name': log[1],
            'timestamp': log[2],
            'url': log[3],
            'action': log[4],
            'message': log[5]
        })

    return jsonify({'logs': log_list, 'request_count': request_count})

# API to log activity from the Chrome extension
@app.route('/api/log', methods=['POST'])
def log_activity():
    data = request.json
    student_name = data.get('studentName', 'Unknown')
    timestamp = data.get('timestamp')
    url = data.get('url')
    action = get_action_from_url(url)
    message = ', '.join(data.get('userMessages', []))

    # Store the log in the SQLite database
    conn = sqlite3.connect('activity_logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (student_name, timestamp, url, action, message)
        VALUES (?, ?, ?, ?, ?)
    ''', (student_name, timestamp, url, action, message))
    conn.commit()
    conn.close()

    return jsonify({'status': 'success'}), 200

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)

