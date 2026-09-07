#!/usr/bin/env python3
"""
SSH Honeypot - A fake SSH server to log and monitor attack attempts
"""

import socket
import threading
import datetime
import paramiko
import os
import sys
import time
import logging
from logging.handlers import RotatingFileHandler

# =============================================
# Configuration
# =============================================

HOST = '0.0.0.0'
PORT = 2222
LOG_FILE = 'honeypot.log'
MAX_LOG_SIZE = 10 * 1024 * 1024
BACKUP_COUNT = 5

# Fake credentials
FAKE_USERS = {
    'root': 'password123',
    'admin': 'admin123',
    'user': 'user123',
    'test': 'test123',
    'ubuntu': 'ubuntu',
    'debian': 'debian',
    'oracle': 'oracle',
    'postgres': 'postgres',
    'mysql': 'mysql',
    'ftpuser': 'ftpuser',
    'nagios': 'nagios',
    'tomcat': 'tomcat',
    'jenkins': 'jenkins',
    'docker': 'docker',
    'k8s': 'k8sadmin',
    'kali': 'kali',
    'pi': 'raspberry',
    'dev': 'dev123',
    'testuser': 'testpass'
}

# Dangerous commands
DANGEROUS_COMMANDS = [
    'rm', 'dd', 'mkfs', 'format', 'shutdown', 'reboot',
    'kill', 'pkill', 'systemctl stop', 'service stop',
    'chmod 777', 'chown', 'passwd', 'useradd', 'userdel',
    'wget', 'curl', 'nc', 'netcat', 'telnet', 'ssh',
    'python -c', 'perl -e', 'bash -c', 'sh -c'
]

# =============================================
# Setup Logging
# =============================================

def setup_logging():
    logger = logging.getLogger('honeypot')
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)
    logger.addHandler(console)
    return logger

logger = setup_logging()

# =============================================
# Core Functions
# =============================================

def log_attempt(ip, username, password, status):
    timestamp = datetime.datetime.now().isoformat()
    if status == 'SUCCESS':
        print(f"\033[92m[{timestamp}] \033[93m{ip}\033[0m - {username}:{password} - \033[92m✅ {status}\033[0m")
    else:
        print(f"[{timestamp}] {ip} - {username}:{password} - ❌ {status}")
    logger.info(f"[{timestamp}] {ip} - {username}:{password} - {status}")

def log_command(ip, username, command, is_dangerous=False):
    """
    Log a command a session ran.

    NOTE: the "DANGEROUS" marker is only ever written to the console
    (with a bell/emoji) and NOT appended to the log file's command text.
    interface.py parses the command field back out of the log line, so
    appending any suffix there would corrupt the stored command (e.g.
    "rm -rf /" would come back as "rm -rf / DANGEROUS"). The dashboard
    does its own dangerous-command detection independently, so nothing
    is lost by keeping the log line clean.
    """
    timestamp = datetime.datetime.now().isoformat()
    danger_console_marker = " 🚨" if is_dangerous else ""
    print(f"[{timestamp}] \033[93m{ip}\033[0m - {username} ran: \033[94m{command}\033[0m{danger_console_marker}")
    logger.info(f"[{timestamp}] {ip} - {username} ran: {command}")

def is_dangerous_command(command):
    cmd_lower = command.lower()
    return any(dangerous in cmd_lower for dangerous in DANGEROUS_COMMANDS)

def get_fake_response(command, username="user"):
    cmd = command.strip()
    if not cmd:
        return ''
    
    # Basic commands
    if cmd == 'ls':
        return 'Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos\n'
    if cmd == 'whoami':
        return f'{username}\n'
    if cmd == 'id':
        return 'uid=0(root) gid=0(root) groups=0(root)\n'
    if cmd == 'pwd':
        return '/root\n'
    if cmd == 'date':
        return datetime.datetime.now().strftime('%a %b %d %H:%M:%S UTC %Y\n')
    if cmd == 'uname -a':
        return 'Linux honeypot 5.15.0-76-generic #83-Ubuntu SMP x86_64 GNU/Linux\n'
    if cmd == 'uname':
        return 'Linux\n'
    if cmd == 'help':
        return 'Available: ls, whoami, id, pwd, date, uname, cat, ps, netstat, df, echo, history, exit\n'
    if cmd == 'exit' or cmd == 'logout' or cmd == 'quit':
        return 'logout\n'
    if cmd == 'history':
        return '    1  ls\n    2  whoami\n    3  pwd\n    4  date\n'
    if cmd == 'clear':
        return ''
    if cmd.startswith('echo '):
        return cmd[5:] + '\n'
    if cmd.startswith('cd '):
        return ''
    if cmd == 'cd':
        return ''
    
    return f'bash: {cmd}: command not found\n'

class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.username = None
        self.event = threading.Event()
    
    def check_auth_password(self, username, password):
        self.username = username
        if username in FAKE_USERS and FAKE_USERS[username] == password:
            log_attempt(self.client_ip, username, password, 'SUCCESS')
            return paramiko.AUTH_SUCCESSFUL
        else:
            log_attempt(self.client_ip, username, password, 'FAILED')
            time.sleep(0.5)
            return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        return 'password'
    
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    def check_channel_exec_request(self, channel, command):
        cmd = command.decode('utf-8') if isinstance(command, bytes) else command
        # FIX: this path (non-interactive `ssh host "command"`) previously never
        # flagged dangerous commands at all - it called log_command() with the
        # default is_dangerous=False. Compute it the same way the interactive
        # shell path does, so direct one-liner commands are flagged too.
        dangerous = is_dangerous_command(cmd)
        log_command(self.client_ip, self.username, cmd, dangerous)
        response = get_fake_response(cmd, self.username)
        channel.send(response.encode())
        channel.send_exit_status(0)
        return True

def shell_thread(channel, client_ip, username):
    try:
        channel.send('\r\n')
        channel.send('Welcome to Ubuntu 22.04.3 LTS\r\n')
        channel.send('\r\n')
        channel.send(f'Last login: {datetime.datetime.now().strftime("%a %b %d %H:%M:%S")} from {client_ip}\r\n')
        channel.send('\r\n')
        
        while True:
            prompt = f'\x1b[01;32m{username}@honeypot\x1b[00m:\x1b[01;34m~$\x1b[00m '
            channel.send(prompt)
            
            command = ''
            while True:
                try:
                    char = channel.recv(1)
                    if not char:
                        return
                    char = char.decode('utf-8', errors='ignore')
                    
                    if char == '\r' or char == '\n':
                        break
                    elif char == '\x7f' or char == '\x08':
                        if command:
                            command = command[:-1]
                            channel.send('\x08 \x08')
                    elif char == '\x03':
                        command = ''
                        channel.send('^C\r\n')
                        break
                    else:
                        command += char
                        channel.send(char)
                except:
                    return
            
            command = command.strip()
            if not command:
                continue
            
            if command.lower() in ['exit', 'logout', 'quit']:
                channel.send('logout\r\n')
                break
            
            dangerous = is_dangerous_command(command)
            log_command(client_ip, username, command, dangerous)
            response = get_fake_response(command, username)
            
            if response:
                channel.send('\r\n')
                channel.send(response)
                if not response.endswith('\n'):
                    channel.send('\r\n')
            channel.send('\r\n')
            
    except Exception as e:
        logger.error(f"Shell error: {e}")
    finally:
        try:
            channel.close()
        except:
            pass

def load_or_create_host_key(key_file):
    """
    Load the persistent host key, generating and saving one if it
    doesn't exist yet or can't be read.

    FIX: the previous version saved keys with `f.write(key.__str__())`.
    RSAKey.__str__() returns the *public* key blob (base64), not a
    valid private-key PEM - so the saved file was never actually
    loadable, from_private_key_file() always raised, and a brand new
    host key was silently generated on every single restart. That
    means every reconnecting client saw a "host key has changed"
    warning, defeating the entire point of persisting a key.

    The fix is to use write_private_key_file(), which is the correct
    paramiko API for saving a key that can be reloaded later.
    """
    if os.path.exists(key_file):
        try:
            return paramiko.RSAKey.from_private_key_file(key_file)
        except Exception:
            pass  # fall through and regenerate below
    host_key = paramiko.RSAKey.generate(2048)
    host_key.write_private_key_file(key_file)
    return host_key

def handle_client(client_socket, client_addr):
    client_ip = client_addr[0]
    print(f"🌐 New connection from: {client_ip}")
    
    try:
        transport = paramiko.Transport(client_socket)
        host_key = load_or_create_host_key('host_rsa_key')
        transport.add_server_key(host_key)
        
        server = HoneypotSSHServer(client_ip)
        transport.start_server(server=server)
        
        channel = transport.accept(30)
        if channel is None:
            print(f"❌ No channel from {client_ip}")
            return
        
        username = server.username or 'root'
        print(f"✅ Channel accepted for {client_ip} as {username}")
        
        shell_thread(channel, client_ip, username)
        
    except Exception as e:
        print(f"❌ Error with {client_ip}: {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass

def main():
    try:
        import paramiko
    except ImportError:
        print("❌ paramiko not installed. Run: pip3 install paramiko")
        sys.exit(1)
    
    # Generate/load the host key up front so startup fails fast if it can't.
    load_or_create_host_key('host_rsa_key')
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(100)
    except Exception as e:
        print(f"❌ Failed to bind: {e}")
        sys.exit(1)
    
    print("=" * 70)
    print("🔐  SSH HONEYPOT")
    print("=" * 70)
    print(f"📡 Listening on: {HOST}:{PORT}")
    print(f"📝 Logging to: {LOG_FILE}")
    print("=" * 70)
    print("📋 Credentials:")
    for user, passwd in FAKE_USERS.items():
        print(f"   👤 {user}  🔑 {passwd}")
    print("=" * 70)
    print(f"✅ Connect: ssh -p {PORT} root@localhost")
    print("   Press Ctrl+C to stop")
    print("=" * 70)
    
    try:
        while True:
            client_socket, client_addr = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(client_socket, client_addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n🛑 Stopping honeypot...")
        server_socket.close()
        sys.exit(0)

if __name__ == '__main__':
    main()
