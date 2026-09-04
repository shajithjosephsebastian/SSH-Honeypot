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
import socket
import requests
from urllib.parse import urlencode

app = Flask(__name__)
LOG_FILE = 'honeypot.log'
MAX_LOGS = 2000

log_cache = deque(maxlen=MAX_LOGS)
cache_lock = Lock()
last_read_pos = 0
is_running = True
clients = []

# GeoIP cache to avoid rate limiting
geo_cache = {}
geo_cache_lock = Lock()

# Track active brute force attacks
active_attacks = {}
attack_lock = Lock()
notified_ips = set()
notified_timestamps = {}

def get_geoip(ip):
    """Get GeoIP information for an IP address using free API"""
    if ip in ['127.0.0.1', 'localhost', '0.0.0.0', '::1']:
        return {'country': 'Local', 'city': 'Local', 'flag': '🏠', 'country_code': 'LO'}
    
    # Check cache first
    with geo_cache_lock:
        if ip in geo_cache:
            return geo_cache[ip]
    
    try:
        # Using free ip-api.com
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
    except Exception as e:
        pass
    
    result = {'country': 'Unknown', 'city': 'Unknown', 'flag': '🌐', 'country_code': 'UN'}
    with geo_cache_lock:
        geo_cache[ip] = result
    return result

def get_country_flag(country_code):
    """Get emoji flag for country code"""
    flags = {
        'US': '🇺🇸', 'GB': '🇬🇧', 'CN': '🇨🇳', 'RU': '🇷🇺', 'DE': '🇩🇪',
        'FR': '🇫🇷', 'JP': '🇯🇵', 'IN': '🇮🇳', 'BR': '🇧🇷', 'CA': '🇨🇦',
        'AU': '🇦🇺', 'KR': '🇰🇷', 'IT': '🇮🇹', 'ES': '🇪🇸', 'NL': '🇳🇱',
        'SE': '🇸🇪', 'NO': '🇳🇴', 'DK': '🇩🇰', 'FI': '🇫🇮', 'PL': '🇵🇱',
        'UA': '🇺🇦', 'RO': '🇷🇴', 'TR': '🇹🇷', 'IL': '🇮🇱', 'SA': '🇸🇦',
        'AE': '🇦🇪', 'SG': '🇸🇬', 'MY': '🇲🇾', 'ID': '🇮🇩', 'PH': '🇵🇭',
        'VN': '🇻🇳', 'TH': '🇹🇭', 'NZ': '🇳🇿', 'ZA': '🇿🇦', 'EG': '🇪🇬',
        'NG': '🇳🇬', 'KE': '🇰🇪', 'AR': '🇦🇷', 'CL': '🇨🇱', 'CO': '🇨🇴',
        'MX': '🇲🇽', 'PE': '🇵🇪', 'VE': '🇻🇪', 'PK': '🇵🇰', 'BD': '🇧🇩',
        'IR': '🇮🇷', 'IQ': '🇮🇶', 'SY': '🇸🇾', 'JO': '🇯🇴', 'LB': '🇱🇧',
        'KW': '🇰🇼', 'QA': '🇶🇦', 'OM': '🇴🇲', 'YE': '🇾🇪', 'BH': '🇧🇭',
        'HK': '🇭🇰', 'TW': '🇹🇼', 'MO': '🇲🇴', 'KP': '🇰🇵', 'MN': '🇲🇳'
    }
    return flags.get(country_code, '🌐')

def is_attack_active(ip):
    """Check if an IP is currently performing a brute force attack"""
    with attack_lock:
        if ip in active_attacks:
            # Check if attack is still active (within last 5 minutes)
            last_seen = active_attacks[ip]
            if (datetime.datetime.now() - last_seen).seconds < 300:  # 5 minutes
                return True
            else:
                # Attack expired
                del active_attacks[ip]
                return False
    return False

def update_attack_activity(ip):
    """Update the last seen time for an attack"""
    with attack_lock:
        active_attacks[ip] = datetime.datetime.now()

def get_attack_patterns():
    """Analyze attack patterns from logs"""
    with cache_lock:
        logs = list(log_cache)
    
    patterns = {
        'top_usernames': {},
        'top_passwords': {},
        'attack_types': {
            'bruteforce': 0,
            'dictionary': 0,
            'password_spray': 0
        },
        'hourly_activity': [0] * 24,
        'daily_activity': [0] * 7,
        'geo_distribution': {},
        'unique_ips': set(),
        'successful_ips': set(),
        'failed_ips': set(),
        'total_auth': 0,
        'total_failed': 0,
        'total_success': 0,
        'total_commands': 0,
        'attack_score': 0
    }
    
    # Track failed attempts per IP for attack detection
    ip_failed_attempts = {}
    
    for log in logs:
        if log.get('type') == 'auth':
            ip = log.get('ip')
            username = log.get('username', '')
            password = log.get('password', '')
            status = log.get('status')
            geo = log.get('geo', {})
            
            patterns['total_auth'] += 1
            
            if status == 'SUCCESS':
                patterns['total_success'] += 1
                patterns['successful_ips'].add(ip)
            else:
                patterns['total_failed'] += 1
                patterns['failed_ips'].add(ip)
                
                # Track failed attempts per IP
                if ip not in ip_failed_attempts:
                    ip_failed_attempts[ip] = []
                ip_failed_attempts[ip].append(log)
                
                # Update attack activity for brute force detection
                update_attack_activity(ip)
            
            patterns['unique_ips'].add(ip)
            
            # Track usernames
            if username:
                patterns['top_usernames'][username] = patterns['top_usernames'].get(username, 0) + 1
            
            # Track passwords
            if password:
                patterns['top_passwords'][password] = patterns['top_passwords'].get(password, 0) + 1
            
            # Geo distribution
            country = geo.get('country', 'Unknown')
            patterns['geo_distribution'][country] = patterns['geo_distribution'].get(country, 0) + 1
            
            # Time-based analysis
            if log.get('timestamp'):
                try:
                    dt = datetime.datetime.fromisoformat(log['timestamp'])
                    patterns['hourly_activity'][dt.hour] += 1
                    patterns['daily_activity'][dt.weekday()] += 1
                except:
                    pass
        
        elif log.get('type') == 'command':
            patterns['total_commands'] += 1
    
    # Detect attack types
    for ip, attempts in ip_failed_attempts.items():
        if len(attempts) >= 5:
            patterns['attack_types']['bruteforce'] += 1
            
            # Check for dictionary attack (many different passwords)
            passwords = set(a.get('password', '') for a in attempts if a.get('password'))
            if 3 <= len(passwords) <= 15:
                patterns['attack_types']['dictionary'] += 1
            
            # Check for password spraying (same password, different usernames)
            usernames = set(a.get('username', '') for a in attempts if a.get('username'))
            if len(usernames) >= 3 and len(passwords) <= 2:
                patterns['attack_types']['password_spray'] += 1
    
    # Calculate attack score (0-100)
    total_attempts = patterns['total_auth'] or 1
    failed_ratio = patterns['total_failed'] / total_attempts
    unique_ratio = len(patterns['unique_ips']) / (total_attempts or 1)
    
    patterns['attack_score'] = min(100, int(
        (failed_ratio * 60) +  # 60% weight on failure ratio
        (unique_ratio * 20) +   # 20% weight on unique IPs
        (patterns['attack_types']['bruteforce'] * 5)  # 20% weight on brute force
    ))
    
    # Sort and limit
    patterns['top_usernames'] = dict(sorted(patterns['top_usernames'].items(), key=lambda x: x[1], reverse=True)[:20])
    patterns['top_passwords'] = dict(sorted(patterns['top_passwords'].items(), key=lambda x: x[1], reverse=True)[:20])
    
    # Convert sets to counts
    patterns['unique_ips_count'] = len(patterns['unique_ips'])
    patterns['successful_ips_count'] = len(patterns['successful_ips'])
    patterns['failed_ips_count'] = len(patterns['failed_ips'])
    
    return patterns

def parse_log_line(line):
    """Parse a log line into structured data with GeoIP"""
    try:
        line = line.strip()
        
        # Format 1: [timestamp] ip - username:password - STATUS
        # Example: [2026-08-19T15:13:40.190154] 192.168.0.139 - admin:pasdf - ❌ FAILED
        auth_match = re.match(r'\[(.*?)\]\s+([\d.]+)\s+-\s+([^:]+):(.+?)\s+-\s+[✅❌]?\s*(\w+)$', line)
        if auth_match:
            timestamp, ip, username, password, status = auth_match.groups()
            geo = get_geoip(ip.strip())
            return {
                'timestamp': timestamp,
                'ip': ip.strip(),
                'username': username.strip(),
                'password': password.strip(),
                'status': status.strip(),
                'type': 'auth',
                'geo': geo
            }
        
        # Format 2: [timestamp] ip - username ran: command
        # Example: [2026-08-19T15:13:52.411375] 192.168.0.139 - admin ran: ls
        cmd_match = re.match(r'\[(.*?)\]\s+([\d.]+)\s+-\s+([^\s]+)\s+ran:\s+(.+)$', line)
        if cmd_match:
            timestamp, ip, username, command = cmd_match.groups()
            geo = get_geoip(ip.strip())
            return {
                'timestamp': timestamp,
                'ip': ip.strip(),
                'username': username.strip(),
                'command': command.strip(),
                'type': 'command',
                'geo': geo
            }
        
        # Format 3: timestamp | ip | username | password | status
        parts = line.split(' | ')
        if len(parts) >= 5:
            if parts[4].startswith('COMMAND:'):
                geo = get_geoip(parts[1].strip())
                return {
                    'timestamp': parts[0],
                    'ip': parts[1].strip(),
                    'username': parts[2].strip(),
                    'command': parts[4].replace('COMMAND:', '').strip(),
                    'type': 'command',
                    'geo': geo
                }
            else:
                geo = get_geoip(parts[1].strip())
                return {
                    'timestamp': parts[0],
                    'ip': parts[1].strip(),
                    'username': parts[2].strip(),
                    'password': parts[3].strip(),
                    'status': parts[4].strip(),
                    'type': 'auth',
                    'geo': geo
                }
        
        # Format 4: timestamp | ip | username | COMMAND: command
        if ' | ' in line and 'COMMAND:' in line:
            parts = line.split(' | ')
            if len(parts) >= 4:
                geo = get_geoip(parts[1].strip())
                return {
                    'timestamp': parts[0],
                    'ip': parts[1].strip(),
                    'username': parts[2].strip(),
                    'command': parts[3].replace('COMMAND:', '').strip(),
                    'type': 'command',
                    'geo': geo
                }
                
    except Exception as e:
        pass
    return None

def load_initial_logs():
    """Load existing logs from file"""
    with cache_lock:
        log_cache.clear()
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, 'r') as f:
                    lines = f.readlines()
                    for line in lines[-MAX_LOGS:]:
                        parsed = parse_log_line(line)
                        if parsed:
                            log_cache.append(parsed)
                print(f"✅ Loaded {len(log_cache)} logs from {LOG_FILE}")
            except Exception as e:
                print(f"Error reading log file: {e}")

def monitor_logs():
    """Background thread to monitor log file changes and notify clients"""
    global last_read_pos
    
    while is_running:
        time.sleep(0.3)
        
        if not os.path.exists(LOG_FILE):
            continue
            
        try:
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
                                log_cache.append(parsed)
                                new_logs.append(parsed)
                    
                    last_read_pos = f.tell()
                
                if new_logs:
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
    """Simple client class for SSE"""
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
    
    return jsonify(logs[-limit:])

@app.route('/api/stats')
def get_stats():
    """API endpoint to get statistics"""
    with cache_lock:
        logs = list(log_cache)
    
    total_auth = sum(1 for log in logs if log.get('type') == 'auth')
    total_commands = sum(1 for log in logs if log.get('type') == 'command')
    successful_logins = sum(1 for log in logs if log.get('status') == 'SUCCESS')
    failed_logins = sum(1 for log in logs if log.get('status') == 'FAILED')
    unique_ips = len(set(log.get('ip', '') for log in logs if log.get('ip')))
    
    # Count usernames
    username_count = {}
    for log in logs:
        if log.get('type') == 'auth':
            username = log.get('username', '')
            username_count[username] = username_count.get(username, 0) + 1
    
    top_usernames = sorted(username_count.items(), key=lambda x: x[1], reverse=True)[:10]
    
    return jsonify({
        'total_logs': len(logs),
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
    patterns = get_attack_patterns()
    return jsonify(patterns)

@app.route('/api/geo/<ip>')
def get_geo(ip):
    """API endpoint to get GeoIP for a specific IP"""
    geo = get_geoip(ip)
    return jsonify(geo)

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
                yield f"data: {json.dumps(existing_logs[-50:])}\n\n"
            
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

@app.route('/api/clear')
def clear_logs():
    """Clear the log cache (doesn't delete file)"""
    with cache_lock:
        log_cache.clear()
    return jsonify({'status': 'cleared'})

@app.route('/api/export')
def export_logs():
    """Export logs in CSV format"""
    format_type = request.args.get('format', 'csv')
    limit = request.args.get('limit', 1000, type=int)
    
    with cache_lock:
        logs = list(log_cache)[-limit:]
    
    if format_type == 'csv':
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'IP', 'Username', 'Password', 'Status', 'Type', 'Command', 'Country', 'City'])
        
        for log in logs:
            geo = log.get('geo', {})
            writer.writerow([
                log.get('timestamp', ''),
                log.get('ip', ''),
                log.get('username', ''),
                log.get('password', ''),
                log.get('status', ''),
                log.get('type', ''),
                log.get('command', ''),
                geo.get('country', ''),
                geo.get('city', '')
            ])
        
        response = Response(output.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = f'attachment; filename=honeypot_logs_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        return response
    
    elif format_type == 'json':
        return jsonify(logs)
    
    return jsonify({'error': 'Invalid format'}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Load initial logs
    load_initial_logs()
    
    # Start log monitor thread
    monitor_thread = Thread(target=monitor_logs, daemon=True)
    monitor_thread.start()
    
    print("=" * 70)
    print("🌐  SSH HONEYPOT WEB INTERFACE")
    print("=" * 70)
    print(f"📡 Web interface running on: http://localhost:5000")
    print(f"📝 Viewing logs from: {LOG_FILE}")
    print(f"🌍 GeoIP tracking: Enabled")
    print(f"📊 Attack pattern analysis: Enabled")
    print(f"🔒 Brute force notification cooldown: 1 minute")
    print("=" * 70)
    print("✅ Web interface is RUNNING")
    print(f"✅ Loaded {len(log_cache)} logs")
    print("   Press Ctrl+C to stop")
    print("=" * 70)
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n🛑 Stopping web interface...")
        is_running = False
        sys.exit(0)
