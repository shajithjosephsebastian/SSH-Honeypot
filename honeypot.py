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
import re
import json
import logging
from logging.handlers import RotatingFileHandler

# =============================================
# Configuration
# =============================================

HOST = '0.0.0.0'
PORT = 22
LOG_FILE = 'honeypot.log'
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 5

# Fake credentials that the honeypot accepts
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

# Commands that should trigger alerts (dangerous commands)
DANGEROUS_COMMANDS = [
    'rm', 'dd', 'mkfs', 'format', 'shutdown', 'reboot',
    'kill', 'pkill', 'systemctl stop', 'service stop',
    'chmod 777', 'chown', 'passwd', 'useradd', 'userdel',
    'wget', 'curl', 'nc', 'netcat', 'telnet', 'ssh',
    'python -c', 'perl -e', 'bash -c', 'sh -c'
]

# Command aliases for better logging
COMMAND_ALIASES = {
    'ls': 'list files',
    'pwd': 'print working directory',
    'whoami': 'show current user',
    'id': 'show user/group info',
    'uptime': 'show system uptime',
    'date': 'show date/time',
    'uname': 'show system info',
    'df': 'show disk usage',
    'du': 'show directory usage',
    'ps': 'show processes',
    'top': 'show process monitor',
    'netstat': 'show network connections',
    'ifconfig': 'show network interfaces',
    'ip': 'show network config',
    'cat': 'read file',
    'less': 'view file',
    'more': 'view file',
    'head': 'view file start',
    'tail': 'view file end',
    'grep': 'search text',
    'find': 'find files',
    'which': 'locate command',
    'echo': 'print text',
    'history': 'show command history',
    'clear': 'clear screen',
    'exit': 'exit session'
}

# =============================================
# Setup Logging
# =============================================

def setup_logging():
    """Setup rotating file logging"""
    logger = logging.getLogger('honeypot')
    logger.setLevel(logging.INFO)
    
    # Rotating file handler
    handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT
    )
    handler.setLevel(logging.INFO)
    
    # Console handler for terminal output
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    
    # Format
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    console.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.addHandler(console)
    
    return logger

logger = setup_logging()

# =============================================
# Core Functions
# =============================================

def log_attempt(ip, username, password, status):
    """Log authentication attempt"""
    timestamp = datetime.datetime.now().isoformat()
    if status == 'SUCCESS':
        print(f"\033[92m[{timestamp}] \033[93m{ip}\033[0m - {username}:{password} - \033[92m✅ {status}\033[0m")
        logger.info(f"[{timestamp}] {ip} - {username}:{password} - ✅ {status}")
    else:
        print(f"[{timestamp}] {ip} - {username}:{password} - ❌ {status}")
        logger.info(f"[{timestamp}] {ip} - {username}:{password} - ❌ {status}")

def log_command(ip, username, command, is_dangerous=False):
    """Log command execution"""
    timestamp = datetime.datetime.now().isoformat()
    
    # Get command alias if available
    cmd_parts = command.strip().split()
    base_cmd = cmd_parts[0] if cmd_parts else command
    alias = COMMAND_ALIASES.get(base_cmd, '')
    
    # Check if dangerous
    is_dangerous = is_dangerous or any(dangerous in command.lower() for dangerous in DANGEROUS_COMMANDS)
    
    danger_marker = " 🚨" if is_dangerous else ""
    print(f"[{timestamp}] \033[93m{ip}\033[0m - {username} ran: \033[94m{command}\033[0m{danger_marker}")
    
    log_entry = f"[{timestamp}] {ip} - {username} ran: {command}"
    if alias:
        log_entry += f" (alias: {alias})"
    if is_dangerous:
        log_entry += " 🚨 DANGEROUS"
    
    logger.info(log_entry)

def get_fake_response(command, username="user"):
    """Return fake output for commands with more realistic responses"""
    cmd = command.strip()
    cmd_lower = cmd.lower()
    
    # Handle empty commands
    if not cmd:
        return ''
    
    # ===== File System Commands =====
    
    if cmd == 'ls':
        return 'Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos\n'
    
    if cmd == 'ls -la' or cmd == 'ls -l':
        return '''total 48
drwxr-xr-x  5 root root 4096 Aug 19 10:00 .
drwxr-xr-x 22 root root 4096 Aug 19 09:30 ..
-rw-r--r--  1 root root  220 Aug 19 08:00 .bash_logout
-rw-r--r--  1 root root 3771 Aug 19 08:00 .bashrc
-rw-r--r--  1 root root  807 Aug 19 08:00 .profile
drwxr-xr-x  2 root root 4096 Aug 19 08:00 Desktop
drwxr-xr-x  2 root root 4096 Aug 19 08:00 Documents
drwxr-xr-x  2 root root 4096 Aug 19 08:00 Downloads
-rw-r--r--  1 root root  1024 Aug 19 09:00 secret.txt
drwx------  2 root root 4096 Aug 19 08:00 .ssh\n'''
    
    if cmd == 'ls -la /root':
        return '''total 52
drwx------  5 root root 4096 Aug 19 10:00 .
drwxr-xr-x 22 root root 4096 Aug 19 09:30 ..
-rw-r--r--  1 root root  220 Aug 19 08:00 .bash_logout
-rw-r--r--  1 root root 3771 Aug 19 08:00 .bashrc
-rw-r--r--  1 root root  807 Aug 19 08:00 .profile
-rw-r--r--  1 root root   33 Aug 19 09:00 flag.txt
drwxr-xr-x  2 root root 4096 Aug 19 08:00 Desktop
drwxr-xr-x  2 root root 4096 Aug 19 08:00 Documents
drwxr-xr-x  2 root root 4096 Aug 19 08:00 Downloads
-rw-------  1 root root  512 Aug 19 09:30 .mysql_history
drwx------  2 root root 4096 Aug 19 08:00 .ssh\n'''
    
    # ===== System Info Commands =====
    
    if cmd == 'whoami' or cmd == 'who am i':
        return f'{username}\n'
    
    if cmd == 'id':
        return 'uid=0(root) gid=0(root) groups=0(root)\n'
    
    if cmd == 'pwd':
        return '/root\n'
    
    if cmd == 'uptime':
        uptime_seconds = int(time.time() - 172800)  # ~2 days
        days = uptime_seconds // 86400
        hours = (uptime_seconds % 86400) // 3600
        minutes = (uptime_seconds % 3600) // 60
        return f' {days:02d}:{hours:02d}:{minutes:02d} up {days} days, {hours:02d}:{minutes:02d},  1 user,  load average: 0.00, 0.01, 0.05\n'
    
    if cmd == 'date':
        return datetime.datetime.now().strftime('%a %b %d %H:%M:%S UTC %Y\n')
    
    if cmd == 'uname -a':
        return 'Linux honeypot 5.15.0-76-generic #83-Ubuntu SMP Thu Jun 15 19:01:37 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n'
    
    if cmd == 'uname -r':
        return '5.15.0-76-generic\n'
    
    if cmd == 'uname -n':
        return 'honeypot\n'
    
    if cmd == 'uname':
        return 'Linux\n'
    
    # ===== File Reading Commands =====
    
    if cmd == 'cat /etc/passwd':
        return '''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:104::/nonexistent:/usr/sbin/nologin
syslog:x:103:106::/home/syslog:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
user:x:1000:1000:user:/home/user:/bin/bash
honeypot:x:1001:1001:Honeypot User:/home/honeypot:/bin/bash\n'''
    
    if cmd == 'cat /etc/hosts':
        return '''127.0.0.1 localhost
127.0.1.1 honeypot
# The following lines are desirable for IPv6 capable hosts
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters\n'''
    
    if cmd == 'cat /etc/ssh/sshd_config':
        return '''# Package generated configuration file
# See the sshd_config(5) manpage for details
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 768
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding yes
X11DisplayOffset 10
PrintMotd yes
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes\n'''
    
    if cmd == 'cat /root/flag.txt':
        return 'flag{this_is_a_fake_flag_for_honeypot_testing}\n'
    
    if cmd == 'cat /root/secret.txt':
        return 'SECRET: This is a simulated secret file. No real data here.\n'
    
    # ===== Process Commands =====
    
    if cmd == 'ps aux':
        return '''USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1  16836  1200 ?        Ss   Aug18   0:02 /sbin/init
root         2  0.0  0.0      0     0 ?        S    Aug18   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   Aug18   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   Aug18   0:00 [rcu_par_gp]
root         6  0.0  0.0      0     0 ?        I<   Aug18   0:00 [kworker/0:0H]
root         9  0.0  0.0      0     0 ?        I<   Aug18   0:00 [mm_percpu_wq]
root        10  0.0  0.0      0     0 ?        S    Aug18   0:00 [ksoftirqd/0]
root        11  0.0  0.0      0     0 ?        R    Aug18   0:00 [rcu_sched]
root        12  0.0  0.0      0     0 ?        S    Aug18   0:00 [migration/0]
root       500  0.0  0.2  32456  2400 ?        Ss   Aug18   0:00 /usr/sbin/sshd -D
root       600  0.0  0.1  22456  1600 ?        S    Aug18   0:00 /usr/sbin/cron -f
root       700  0.0  0.3  45678  3200 ?        S    Aug18   0:00 /usr/bin/python3 /opt/honeypot.py
user      1000  0.0  0.2  23456  2000 ?        S    Aug18   0:00 /bin/bash\n'''
    
    if cmd == 'top -b -n 1':
        return '''top - 10:00:00 up 2 days,  3:15,  1 user,  load average: 0.00, 0.01, 0.05
Tasks: 124 total,   1 running, 123 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.0 us,  0.0 sy,  0.0 ni,100.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   3920.0 total,   3120.0 free,    500.0 used,    300.0 buff/cache
MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   3420.0 avail Mem 

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    1 root      20   0   16836   1200    800 S   0.0   0.0   0:02.34 init
  500 root      20   0   32456   2400   1800 S   0.0   0.1   0:00.23 sshd
  700 root      20   0   45678   3200   2400 S   0.0   0.1   0:00.45 python3
 1000 user      20   0   23456   2000   1600 S   0.0   0.1   0:00.12 bash\n'''
    
    # ===== Network Commands =====
    
    if cmd == 'netstat -an' or cmd == 'netstat -tulpn':
        return '''Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN
udp        0      0 0.0.0.0:68              0.0.0.0:*
udp        0      0 0.0.0.0:123             0.0.0.0:*
udp6       0      0 :::123                  :::*'''
    
    if cmd == 'ifconfig' or cmd == 'ip addr':
        return '''eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::20c:29ff:fe8a:1b2c  prefixlen 64  scopeid 0x20
        ether 00:0c:29:8a:1b:2c  txqueuelen 1000  (Ethernet)
        RX packets 12345  bytes 12345678 (12.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 6789  bytes 6789012 (6.7 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 123  bytes 12345 (12.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 123  bytes 12345 (12.3 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n'''
    
    # ===== Disk Commands =====
    
    if cmd == 'df -h':
        return '''Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1       100G   30G   70G  30% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
/dev/sdb1       500G  100G  400G  20% /data\n'''
    
    if cmd == 'du -sh /*' or cmd == 'du -sh /':
        return '''4.0K    /bin
4.0K    /boot
4.0K    /dev
8.0K    /etc
4.0K    /home
4.0K    /lib
4.0K    /media
4.0K    /mnt
4.0K    /opt
4.0K    /proc
4.0K    /root
4.0K    /run
4.0K    /sbin
4.0K    /srv
4.0K    /sys
4.0K    /tmp
4.0K    /usr
4.0K    /var\n'''
    
    # ===== User Commands =====
    
    if cmd == 'who':
        return f'root     pts/0        {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")} (192.168.1.100)\n'
    
    if cmd == 'w':
        return f''' 10:00:00 up 2 days,  3:15,  1 user,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     pts/0    192.168.1.100    09:30    0.00s  0.01s  0.00s {command}\n'''
    
    if cmd == 'last':
        return f'''root     pts/0        192.168.1.100   {datetime.datetime.now().strftime("%a %b %d %H:%M")}   still logged in
root     pts/0        192.168.1.100   {datetime.datetime.now().strftime("%a %b %d %H:%M")} - {datetime.datetime.now().strftime("%H:%M")}  (00:05)
user     pts/1        192.168.1.101   {datetime.datetime.now().strftime("%a %b %d %H:%M")} - {datetime.datetime.now().strftime("%H:%M")}  (00:10)
reboot   system boot   {datetime.datetime.now().strftime("%a %b %d %H:%M")}   still running\n'''
    
    # ===== Environment Commands =====
    
    if cmd == 'env':
        return '''SHELL=/bin/bash
TERM=xterm-256color
USER=root
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/root
LANG=en_US.UTF-8
HOME=/root
LOGNAME=root\n'''
    
    if cmd == 'echo $PATH':
        return '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
    
    if cmd == 'echo $HOME':
        return '/root\n'
    
    if cmd == 'echo $USER':
        return 'root\n'
    
    # ===== Other Commands =====
    
    if cmd == 'history':
        return '''    1  ls
    2  whoami
    3  pwd
    4  cat /etc/passwd
    5  ls -la
    6  uname -a
    7  df -h
    8  ps aux
    9  netstat -an
   10  history\n'''
    
    if cmd == 'clear':
        return ''
    
    if cmd == 'help' or cmd == '?':
        return '''Available commands:
  ls              - List files
  ls -la          - List all files with details
  whoami          - Show current user
  id              - Show user/group info
  pwd             - Show current directory
  uptime          - Show system uptime
  date            - Show current date/time
  uname           - Show system info
  cat             - Read files (passwd, hosts, sshd_config, flag.txt, secret.txt)
  ps aux          - Show processes
  top -b -n 1     - Show process monitor
  netstat -an     - Show network connections
  ifconfig        - Show network interfaces
  df -h           - Show disk usage
  du -sh          - Show directory usage
  who             - Show logged in users
  w               - Show system load and users
  last            - Show login history
  env             - Show environment variables
  echo            - Print text
  history         - Show command history
  clear           - Clear screen
  exit            - Exit session\n'''
    
    # ===== Echo Commands =====
    
    if cmd.startswith('echo '):
        return cmd[5:] + '\n'
    
    # ===== CD Commands =====
    
    if cmd.startswith('cd '):
        return ''
    
    if cmd == 'cd':
        return ''
    
    # ===== Unknown Command =====
    
    # Check if it's a command with arguments that we don't handle
    base_cmd = cmd.split()[0] if ' ' in cmd else cmd
    return f'bash: {cmd}: command not found\n'

class HoneypotSSHServer(paramiko.ServerInterface):
    """SSH Server interface for the honeypot"""
    
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.username = None
        self.event = threading.Event()
        self.start_time = datetime.datetime.now()
    
    def check_auth_password(self, username, password):
        """Handle password authentication"""
        self.username = username
        
        # Check if credentials are valid
        if username in FAKE_USERS and FAKE_USERS[username] == password:
            log_attempt(self.client_ip, username, password, 'SUCCESS')
            return paramiko.AUTH_SUCCESSFUL
        else:
            log_attempt(self.client_ip, username, password, 'FAILED')
            # Add random delay to simulate real SSH
            time.sleep(0.5)
            return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        """Disable public key authentication"""
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        """Only allow password authentication"""
        return 'password'
    
    def check_channel_request(self, kind, chanid):
        """Handle channel requests"""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_shell_request(self, channel):
        """Handle shell requests"""
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Handle PTY requests"""
        return True
    
    def check_channel_exec_request(self, channel, command):
        """Handle direct command execution (ssh user@host command)"""
        cmd = command.decode('utf-8') if isinstance(command, bytes) else command
        
        # Log the command
        is_dangerous = any(dangerous in cmd.lower() for dangerous in DANGEROUS_COMMANDS)
        log_command(self.client_ip, self.username, cmd, is_dangerous)
        
        # Get fake response
        response = get_fake_response(cmd, self.username)
        channel.send(response.encode())
        channel.send_exit_status(0)
        return True

def shell_thread(channel, client_ip, username):
    """Interactive shell thread for the honeypot"""
    try:
        # Send welcome banner
        channel.send('\r\n')
        channel.send('Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-76-generic x86_64)\r\n')
        channel.send('\r\n')
        channel.send(' * Documentation:  https://help.ubuntu.com\r\n')
        channel.send(' * Management:     https://landscape.canonical.com\r\n')
        channel.send(' * Support:        https://ubuntu.com/advantage\r\n')
        channel.send('\r\n')
        channel.send(f'  System information as of {datetime.datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")}\r\n')
        channel.send('\r\n')
        channel.send(f'  System load:  0.08              Processes:             124\r\n')
        channel.send(f'  Usage of /:   30.2% of 98.42GB   Users logged in:       1\r\n')
        channel.send(f'  Memory usage: 12%               IPv4 address for eth0:  {client_ip}\r\n')
        channel.send(f'  Swap usage:   0%\r\n')
        channel.send('\r\n')
        channel.send(f'Last login: {datetime.datetime.now().strftime("%a %b %d %H:%M:%S")} from {client_ip}\r\n')
        channel.send('\r\n')
        
        # Main shell loop
        while True:
            # Build prompt with color
            hostname = 'honeypot'
            prompt = f'\x1b[01;32m{username}@{hostname}\x1b[00m:\x1b[01;34m~$\x1b[00m '
            channel.send(prompt)
            
            # Read command character by character
            command = ''
            while True:
                try:
                    char = channel.recv(1)
                    if not char:
                        return
                    char = char.decode('utf-8', errors='ignore')
                    
                    if char == '\r' or char == '\n':
                        break
                    elif char == '\x7f' or char == '\x08':  # Backspace
                        if command:
                            command = command[:-1]
                            channel.send('\x08 \x08')
                    elif char == '\x03':  # Ctrl+C
                        command = ''
                        channel.send('^C\r\n')
                        break
                    elif char == '\x04':  # Ctrl+D
                        channel.send('exit\r\n')
                        command = 'exit'
                        break
                    else:
                        command += char
                        channel.send(char)
                except:
                    return
            
            # Clean command
            command = command.strip()
            
            # Handle empty command
            if not command:
                continue
            
            # Check for exit
            if command.lower() in ['exit', 'logout', 'quit']:
                channel.send('logout\r\n')
                break
            
            # Log the command
            is_dangerous = any(dangerous in command.lower() for dangerous in DANGEROUS_COMMANDS)
            log_command(client_ip, username, command, is_dangerous)
            
            # Get fake response
            response = get_fake_response(command, username)
            
            # Send response with proper formatting
            if response:
                channel.send('\r\n')
                channel.send(response)
                if not response.endswith('\n'):
                    channel.send('\r\n')
            
            channel.send('\r\n')
            
    except Exception as e:
        logger.error(f"Shell error for {client_ip}: {e}")
    finally:
        try:
            channel.close()
        except:
            pass

def handle_client(client_socket, client_addr):
    """Handle incoming client connection"""
    client_ip = client_addr[0]
    try:
        transport = paramiko.Transport(client_socket)
        transport.set_gss_host(socket.getfqdn())
        
        # Load or generate host key
        try:
            host_key = paramiko.RSAKey.from_private_key_file('host_rsa_key')
            transport.add_server_key(host_key)
        except:
            host_key = paramiko.RSAKey.generate(2048)
            transport.add_server_key(host_key)
            # Save the key for future use
            with open('host_rsa_key', 'w') as f:
                f.write(host_key.__str__())
        
        # Start server
        server = HoneypotSSHServer(client_ip)
        transport.start_server(server=server)
        
        # Wait for authentication
        channel = transport.accept(30)
        if channel is None:
            return
        
        # Get username
        username = server.username or 'root'
        
        # Start interactive shell
        shell_thread(channel, client_ip, username)
        
    except Exception as e:
        logger.error(f"Error with {client_ip}: {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass

def main():
    """Main entry point"""
    try:
        import paramiko
    except ImportError:
        print("❌ paramiko not installed. Run: pip3 install paramiko")
        sys.exit(1)
    
    # Generate host keys if not exists
    if not os.path.exists('host_rsa_key'):
        print("🔑 Generating host keys...")
        os.system("ssh-keygen -t rsa -f host_rsa_key -N '' 2>/dev/null")
        print("✅ Host keys generated")
    
    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(100)
    except Exception as e:
        print(f"❌ Failed to bind to port {PORT}: {e}")
        print(f"   Try running with sudo: sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    # Print banner
    print("=" * 70)
    print("🔐  SSH HONEYPOT")
    print("=" * 70)
    print(f"📡 Listening on: {HOST}:{PORT}")
    print(f"📝 Logging to:   {LOG_FILE}")
    print("=" * 70)
    print("📋 Fake credentials:")
    for user, passwd in FAKE_USERS.items():
        print(f"   👤 {user}  🔑 {passwd}")
    print("=" * 70)
    print("✅ Honeypot is RUNNING")
    print("   Press Ctrl+C to stop")
    print("=" * 70)
    print("")
    
    try:
        while True:
            client_socket, client_addr = server_socket.accept()
            client_ip = client_addr[0]
            timestamp = datetime.datetime.now().isoformat()
            print(f"[{timestamp}] 🌐 New connection from: {client_ip}")
            logger.info(f"[{timestamp}] 🌐 New connection from: {client_ip}")
            
            thread = threading.Thread(target=handle_client, args=(client_socket, client_addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n🛑 Stopping honeypot...")
        server_socket.close()
        logger.info("Honeypot stopped")
        sys.exit(0)

if __name__ == '__main__':
    main()
