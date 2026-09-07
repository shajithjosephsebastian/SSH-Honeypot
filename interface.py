#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request, Response, stream_with_context
import datetime
import os
import json
import time
import re
from threading import Thread, Lock
from collections import deque
import sys
import requests

app = Flask(__name__)
LOG_FILE = 'honeypot.log'
MAX_LOGS = 2000

log_cache = deque(maxlen=MAX_LOGS)
cache_lock = Lock()
last_read_pos = 0
file_inode = None
is_running = True
clients = []

# GeoIP cache
geo_cache = {}
geo_cache_lock = Lock()

def get_geoip(ip):
    if ip in ['127.0.0.1', 'localhost', '0.0.0.0', '::1']:
        return {'country': 'Local', 'city': 'Local', 'flag': '🏠', 'country_code': 'LO'}
    
    with geo_cache_lock:
        if ip in geo_cache:
            return geo_cache[ip]
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                result = {
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', ''),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', ''),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', ''),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'flag': get_country_flag(data.get('countryCode', ''))
                }
                with geo_cache_lock:
                    geo_cache[ip] = result
                return result
    except:
        pass
    
    result = {'country': 'Unknown', 'city': 'Unknown', 'flag': '🌐', 'country_code': 'UN'}
    with geo_cache_lock:
        geo_cache[ip] = result
    return result

def get_country_flag(country_code):
    flags = {
        'US': '🇺🇸', 'GB': '🇬🇧', 'CN': '🇨🇳', 'RU': '🇷🇺', 'DE': '🇩🇪',
        'FR': '🇫🇷', 'JP': '🇯🇵', 'IN': '🇮🇳', 'BR': '🇧🇷', 'CA': '🇨🇦',
        'AU': '🇦🇺', 'KR': '🇰🇷', 'IT': '🇮🇹', 'ES': '🇪🇸', 'NL': '🇳🇱',
        'SE': '🇸🇪', 'NO': '🇳🇴', 'DK': '🇩🇰', 'FI': '🇫🇮', 'PL': '🇵🇱',
        'UA': '🇺🇦', 'RO': '🇷🇴', 'TR': '🇹🇷', 'IL': '🇮🇱', 'SA': '🇸🇦',
        'AE': '🇦🇪', 'SG': '🇸🇬', 'MY': '🇲🇾', 'ID': '🇮🇩', 'PH': '🇵🇭',
        'VN': '🇻🇳', 'TH': '🇹🇭', 'NZ': '🇳🇿', 'ZA': '🇿🇦', 'EG': '🇪🇬',
        'NG': '🇳🇬', 'KE': '🇰🇪', 'AR': '🇦🇷', 'CL': '🇨🇱', 'CO': '🇨🇴',
        'MX': '🇲🇽', 'PE': '🇵🇪', 'VE': '🇻🇪', 'PK': '🇵🇰', 'BD': '🇧🇩'
    }
    return flags.get(country_code, '🌐')

def get_file_inode(filepath):
    """Get file inode to detect log rotation"""
    try:
        return os.stat(filepath).st_ino
    except:
        return None

def parse_log_line(line):
    """Parse a log line from your honeypot"""
    try:
        line = line.strip()
        
        # Check if it's a command log
        if 'ran:' in line:
            match = re.search(r'\[(.*?)\]\s+([\d.]+)\s+-\s+([^\s]+)\s+ran:\s+(.+)$', line)
            if match:
                timestamp, ip, username, command = match.groups()
                geo = get_geoip(ip.strip())
                return {
                    'timestamp': timestamp,
                    'ip': ip.strip(),
                    'username': username.strip(),
                    'command': command.strip(),
                    'type': 'command',
                    'geo': geo,
                    '_id': f"{timestamp}_{ip}_{username}_{command[:20]}"  # Unique ID to prevent duplicates
                }
        
        # Check if it's an auth log
        match = re.search(r'\[(.*?)\]\s+([\d.]+)\s+-\s+([^:]+):(.+?)\s+-\s+(SUCCESS|FAILED)$', line)
        if match:
            timestamp, ip, username, password, status = match.groups()
            geo = get_geoip(ip.strip())
            return {
                'timestamp': timestamp,
                'ip': ip.strip(),
                'username': username.strip(),
                'password': password.strip(),
                'status': status.strip(),
                'type': 'auth',
                'geo': geo,
                '_id': f"{timestamp}_{ip}_{username}_{password}"  # Unique ID to prevent duplicates
            }
                
    except Exception as e:
        pass
    return None

def load_initial_logs():
    """Load existing logs from file"""
    global last_read_pos, file_inode
    
    with cache_lock:
        log_cache.clear()
        last_read_pos = 0
        
        if os.path.exists(LOG_FILE):
            try:
                file_inode = get_file_inode(LOG_FILE)
                with open(LOG_FILE, 'r') as f:
                    lines = f.readlines()
                    for line in lines[-MAX_LOGS:]:
                        parsed = parse_log_line(line)
                        if parsed:
                            # Check for duplicates before adding
                            if not any(log.get('_id') == parsed['_id'] for log in log_cache):
                                log_cache.append(parsed)
                    last_read_pos = f.tell()
                print(f"✅ Loaded {len(log_cache)} unique logs from {LOG_FILE}")
            except Exception as e:
                print(f"Error reading log file: {e}")

def monitor_logs():
    """Background thread to monitor log file changes"""
    global last_read_pos, file_inode
    
    while is_running:
        time.sleep(0.5)
        
        if not os.path.exists(LOG_FILE):
            continue
            
        try:
            # Check if file was rotated (inode changed)
            current_inode = get_file_inode(LOG_FILE)
            if current_inode != file_inode:
                print("🔄 Log file rotated, reloading...")
                load_initial_logs()
                continue
            
            current_size = os.path.getsize(LOG_FILE)
            if current_size > last_read_pos:
                new_logs = []
                with open(LOG_FILE, 'r') as f:
                    f.seek(last_read_pos)
                    new_lines = f.readlines()
                    
                    with cache_lock:
                        for line in new_lines:
                            parsed = parse_log_line(line)
                            if parsed:
                                # Check for duplicates before adding
                                if not any(log.get('_id') == parsed['_id'] for log in log_cache):
                                    log_cache.append(parsed)
                                    new_logs.append(parsed)
                    
                    last_read_pos = f.tell()
                
                if new_logs:
                    print(f"📝 Added {len(new_logs)} new logs")
                    notify_clients(new_logs)
        except Exception as e:
            pass

def notify_clients(new_logs):
    """Send new logs to all connected SSE clients"""
    message = f"data: {json.dumps(new_logs)}\n\n"
    for client in clients[:]:
        try:
            client.put(message)
        except:
            clients.remove(client)

class Client:
    def __init__(self):
        self.queue = deque()
        self.active = True
    
    def put(self, data):
        if self.active:
            self.queue.append(data)
    
    def get(self):
        if self.queue:
            return self.queue.popleft()
        return None

# ===== Routes =====

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/logs')
def get_logs():
    """API endpoint to get logs with filters"""
    limit = request.args.get('limit', 100, type=int)
    filter_text = request.args.get('filter', '').lower()
    log_type = request.args.get('type', 'all')
    status = request.args.get('status', 'all')
    ip_filter = request.args.get('ip', '')
    
    with cache_lock:
        logs = list(log_cache)
    
    # Apply filters
    if filter_text:
        logs = [log for log in logs if 
                filter_text in log.get('ip', '').lower() or
                filter_text in log.get('username', '').lower() or
                filter_text in log.get('command', '').lower() or
                filter_text in log.get('password', '').lower()]
    
    if log_type != 'all':
        logs = [log for log in logs if log.get('type') == log_type]
    
    if status != 'all':
        logs = [log for log in logs if log.get('status') == status]
    
    if ip_filter:
        logs = [log for log in logs if log.get('ip') == ip_filter]
    
    # Remove duplicates based on _id
    seen = set()
    unique_logs = []
    for log in logs[-limit:]:
        log_id = log.get('_id', log.get('timestamp', '') + log.get('ip', ''))
        if log_id not in seen:
            seen.add(log_id)
            unique_logs.append(log)
    
    return jsonify(unique_logs)

@app.route('/api/stats')
def get_stats():
    """API endpoint to get statistics"""
    with cache_lock:
        logs = list(log_cache)
    
    # Remove duplicates for stats
    seen = set()
    unique_logs = []
    for log in logs:
        log_id = log.get('_id', log.get('timestamp', '') + log.get('ip', ''))
        if log_id not in seen:
            seen.add(log_id)
            unique_logs.append(log)
    
    total_auth = sum(1 for log in unique_logs if log.get('type') == 'auth')
    total_commands = sum(1 for log in unique_logs if log.get('type') == 'command')
    successful_logins = sum(1 for log in unique_logs if log.get('status') == 'SUCCESS')
    failed_logins = sum(1 for log in unique_logs if log.get('status') == 'FAILED')
    unique_ips = len(set(log.get('ip', '') for log in unique_logs if log.get('ip')))
    
    username_count = {}
    for log in unique_logs:
        if log.get('type') == 'auth':
            username = log.get('username', '')
            username_count[username] = username_count.get(username, 0) + 1
    
    top_usernames = sorted(username_count.items(), key=lambda x: x[1], reverse=True)[:10]
    
    return jsonify({
        'total_logs': len(unique_logs),
        'total_auth_attempts': total_auth,
        'total_commands': total_commands,
        'successful_logins': successful_logins,
        'failed_logins': failed_logins,
        'unique_ips': unique_ips,
        'top_usernames': dict(top_usernames)
    })

@app.route('/api/patterns')
def get_patterns():
    """API endpoint to get attack patterns"""
    with cache_lock:
        logs = list(log_cache)
    
    # Remove duplicates
    seen = set()
    unique_logs = []
    for log in logs:
        log_id = log.get('_id', log.get('timestamp', '') + log.get('ip', ''))
        if log_id not in seen:
            seen.add(log_id)
            unique_logs.append(log)
    
    patterns = {
        'top_usernames': {},
        'top_passwords': {},
        'attack_types': {'bruteforce': 0, 'dictionary': 0, 'password_spray': 0},
        'geo_distribution': {},
        'total_auth': 0,
        'total_success': 0,
        'total_failed': 0,
        'total_commands': 0,
        'attack_score': 0
    }
    
    ip_failed = {}
    
    for log in unique_logs:
        if log.get('type') == 'auth':
            ip = log.get('ip')
            username = log.get('username', '')
            password = log.get('password', '')
            status = log.get('status')
            geo = log.get('geo', {})
            
            patterns['total_auth'] += 1
            
            if status == 'SUCCESS':
                patterns['total_success'] += 1
            else:
                patterns['total_failed'] += 1
                if ip not in ip_failed:
                    ip_failed[ip] = []
                ip_failed[ip].append(log)
            
            if username:
                patterns['top_usernames'][username] = patterns['top_usernames'].get(username, 0) + 1
            if password:
                patterns['top_passwords'][password] = patterns['top_passwords'].get(password, 0) + 1
            
            country = geo.get('country', 'Unknown')
            patterns['geo_distribution'][country] = patterns['geo_distribution'].get(country, 0) + 1
        
        elif log.get('type') == 'command':
            patterns['total_commands'] += 1
    
    # Detect attack types
    for ip, attempts in ip_failed.items():
        if len(attempts) >= 5:
            patterns['attack_types']['bruteforce'] += 1
    
    # Calculate attack score
    total = patterns['total_auth'] or 1
    failed_ratio = patterns['total_failed'] / total
    patterns['attack_score'] = min(100, int(failed_ratio * 100))
    
    patterns['top_usernames'] = dict(sorted(patterns['top_usernames'].items(), key=lambda x: x[1], reverse=True)[:20])
    patterns['top_passwords'] = dict(sorted(patterns['top_passwords'].items(), key=lambda x: x[1], reverse=True)[:20])
    
    return jsonify(patterns)

@app.route('/api/stream')
def stream():
    """SSE endpoint for real-time updates"""
    client = Client()
    clients.append(client)
    
    def generate():
        try:
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"
            
            with cache_lock:
                existing_logs = list(log_cache)
            if existing_logs:
                # Send unique logs only
                seen = set()
                unique_logs = []
                for log in existing_logs[-50:]:
                    log_id = log.get('_id', log.get('timestamp', '') + log.get('ip', ''))
                    if log_id not in seen:
                        seen.add(log_id)
                        unique_logs.append(log)
                yield f"data: {json.dumps(unique_logs)}\n\n"
            
            while is_running and client.active:
                data = client.get()
                if data:
                    yield data
                else:
                    yield f": heartbeat\n\n"
                    time.sleep(0.5)
        except GeneratorExit:
            client.active = False
            if client in clients:
                clients.remove(client)
        except Exception as e:
            print(f"SSE error: {e}")
            if client in clients:
                clients.remove(client)
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/api/export')
def export_logs():
    """Export logs in CSV format"""
    limit = request.args.get('limit', 1000, type=int)
    
    with cache_lock:
        logs = list(log_cache)
    
    # Remove duplicates
    seen = set()
    unique_logs = []
    for log in logs[-limit:]:
        log_id = log.get('_id', log.get('timestamp', '') + log.get('ip', ''))
        if log_id not in seen:
            seen.add(log_id)
            unique_logs.append(log)
    
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'IP', 'Username', 'Password', 'Status', 'Type', 'Command', 'Country'])
    
    for log in unique_logs:
        geo = log.get('geo', {})
        writer.writerow([
            log.get('timestamp', ''),
            log.get('ip', ''),
            log.get('username', ''),
            log.get('password', ''),
            log.get('status', ''),
            log.get('type', ''),
            log.get('command', ''),
            geo.get('country', '')
        ])
    
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = f'attachment; filename=honeypot_logs_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    return response

@app.route('/api/clear-cache')
def clear_cache():
    """Clear the log cache"""
    with cache_lock:
        log_cache.clear()
    return jsonify({'status': 'cleared'})

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

if __name__ == '__main__':
    load_initial_logs()
    
    monitor_thread = Thread(target=monitor_logs, daemon=True)
    monitor_thread.start()
    
    print("=" * 70)
    print("🌐  SSH HONEYPOT WEB INTERFACE")
    print("=" * 70)
    print(f"📡 Web interface running on: http://localhost:5000")
    print(f"📝 Reading logs from: {LOG_FILE}")
    print(f"✅ Loaded {len(log_cache)} unique logs")
    print("=" * 70)
    print("✅ Web interface is RUNNING")
    print("   Press Ctrl+C to stop")
    print("=" * 70)
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n🛑 Stopping web interface...")
        is_running = False
        sys.exit(0)