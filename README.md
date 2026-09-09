# SSH Honeypot & Live Threat Dashboard

A Python-based SSH honeypot that captures real attack traffic and a live web dashboard for monitoring and investigating attacker activity.

The project records authentication attempts, credentials, commands, and attacker IPs, while detecting basic attack patterns such as brute-force, dictionary attacks, and password spraying.

Built as a hands-on cybersecurity project to learn about **SSH, honeypots, logging, threat detection, and security monitoring dashboards**.

## Dashboard

![SSH Honeypot Dashboard](https://github.com/user-attachments/assets/cc34d0bf-d0aa-4d22-ad05-057ad8c980e0)

![Dashboard Activity](https://github.com/user-attachments/assets/cb0abae0-a078-444b-a9d4-bc9854f38a87)

## Session Investigation

![SSH Session Details](https://github.com/user-attachments/assets/327eb28e-5623-4337-8b2d-64d470165902)

## Features

### SSH Honeypot

* Fake SSH server built with **Paramiko**
* Accepts connections on a configurable port
* Intentionally weak decoy credentials
* Simulated interactive shell
* Realistic responses for common Linux commands
* Logs authentication attempts and commands
* Persistent SSH host key
* No real shell or system command execution

### Threat Dashboard

* Live attack monitoring
* Real-time event streaming using **Server-Sent Events (SSE)**
* Attacker IP tracking
* GeoIP information
* Threat scoring
* Brute-force detection
* Dictionary attack detection
* Password-spray detection
* Successful-login alerts
* Failed-login burst alerts
* Session investigation
* Command history
* Dangerous-command detection
* Session replay
* Log filtering and sorting
* CSV log export
* Firewall blocking command generation for `iptables`, `ufw`, and `fail2ban`

> The dashboard only generates firewall commands for the operator to copy. It does **not** modify the firewall automatically.

## Requirements

* Python 3.8+
* Linux recommended
* No root privileges required when using the default port `2222`

## Installation & Usage

Clone the repository:

```bash
git clone https://github.com/shajithjosephsebastian/SSH-Honeypot.git
cd SSH-Honeypot
```

### Quick Start

The easiest way to run the project is with the included `run.sh` script.

```bash
./run.sh
```

The script handles the setup automatically:

* Creates the Python virtual environment
* Installs the required dependencies
* Checks the required ports
* Starts the SSH honeypot
* Starts the Flask web dashboard

You don't need to manually create the virtual environment or run
`pip install` when using `run.sh`.

Once started, the honeypot uses:

```text
SSH Honeypot: 2222
Dashboard:    5000
```

Open the dashboard in your browser:

```text
http://localhost:5000
```

### Manual Setup

If you prefer to run the components separately, you can set them up manually:

```bash
python3 -m venv honeypot-env
source honeypot-env/bin/activate
pip install -r requirements.txt
```

Start the honeypot:

```bash
python3 honeypot.py
```

In another terminal, activate the virtual environment and start the dashboard:

```bash
source honeypot-env/bin/activate
python3 interface.py
```

The dashboard will be available at:

```text
http://localhost:5000
```

## Testing the Honeypot

With the honeypot running on the default port `2222`:

```bash
ssh -p 2222 root@localhost
```

Try an incorrect password first, followed by one of the accepted decoy
credentials.

The available credentials can be found in `FAKE_USERS` inside:

```text
honeypot.py
```

All credentials are intentionally fake and should only be used by the
honeypot.

---

# Running the Honeypot on Port 22

If you want the honeypot to look like a normal SSH server to internet scanners, you can run the honeypot on the standard SSH port `22`.

However, **your existing SSH server is probably already using port 22**.

You must first move the real SSH server to another port, such as `2222`.

## 1. Change the Real SSH Server to Port 2222

Edit the SSH server configuration:

```bash
sudo nano /etc/ssh/sshd_config
```

Find:

```text
#Port 22
```

or:

```text
Port 22
```

Change it to:

```text
Port 2222
```

If you see an existing `Port` line, make sure there is only one active port configuration.

Save the file.

### Allow port 2222 through the firewall

If you use UFW:

```bash
sudo ufw allow 2222/tcp
```

Check the rules:

```bash
sudo ufw status
```

## 2. Restart the Real SSH Server

On most modern Linux distributions:

```bash
sudo systemctl restart ssh
```

If that doesn't work, try:

```bash
sudo systemctl restart sshd
```

Check that SSH is listening on port `2222`:

```bash
sudo ss -tlnp | grep 2222
```

You should see something similar to:

```text
LISTEN 0 128 0.0.0.0:2222
```

## 3. Test the Real SSH Server

**Do not close your existing SSH session until you have confirmed that the new port works.**

Open another terminal and test:

```bash
ssh -p 2222 username@your-server-ip
```

If you can successfully connect, your real SSH server is now running on port `2222`.

## 4. Change the Honeypot to Port 22

Open:

```text
honeypot.py
```

Find:

```python
PORT = 2222
```

Change it to:

```python
PORT = 22
```

Because ports below `1024` are privileged on Linux, the honeypot must now be started with elevated privileges:

```bash
sudo python3 honeypot.py
```

The honeypot will now listen on:

```text
0.0.0.0:22
```

while your real SSH server remains on:

```text
0.0.0.0:2222
```

Your setup will therefore look like:

```text
Internet
   │
   ├── TCP 22 ────> SSH Honeypot
   │
   └── TCP 2222 ──> Real SSH Server
```

## Important

Make sure port `2222` remains accessible before moving the honeypot to port `22`.

If you are connected to the server through SSH, changing the SSH configuration incorrectly can lock you out.

Always:

1. Keep your existing SSH session open.
2. Change SSH to `2222`.
3. Allow `2222` through the firewall.
4. Restart SSH.
5. Test a **new** SSH connection on `2222`.
6. Only after confirming it works, start the honeypot on `22`.

For an internet-facing honeypot, using a **separate VM or dedicated machine** is strongly recommended.

---

# Decoy Credentials

The honeypot contains intentionally weak credentials that attackers can use to enter the simulated shell.

They are defined in:

```python
FAKE_USERS
```

Example:

```python
FAKE_USERS = {
    "root": "password123",
    "admin": "admin123",
    "pi": "raspberry"
}
```

You can modify these to simulate different credentials.

**Never use these credentials for any real account.**

---

# Dashboard API

| Endpoint                     | Description                           |
| ---------------------------- | ------------------------------------- |
| `GET /api/logs`              | Retrieve recent log entries           |
| `GET /api/stats`             | Dashboard statistics                  |
| `GET /api/patterns`          | Attack-pattern analysis               |
| `GET /api/geo/<ip>`          | GeoIP information                     |
| `GET /api/stream`            | Real-time SSE event stream            |
| `GET /api/export?format=csv` | Export logs as CSV                    |
| `GET /api/clear-cache`       | Clear the dashboard's in-memory cache |

## Security Notes

This project is intended for **educational and security research purposes**.

If you expose the honeypot to the internet:

* Run it on an isolated VM, container, or dedicated machine.
* Do not run it on a system containing sensitive information.
* Keep the dashboard (`port 5000`) inaccessible from the public internet.
* Treat all attacker input and captured data as untrusted.
* Do not commit logs, SSH keys, passwords, or environment files to Git.
* Remember that GeoIP lookups use an external API.

The honeypot provides a **simulated shell**. It does not execute attacker commands on the underlying operating system.

## What I Learned

This project started as a simple fake SSH server and evolved into a small security-monitoring pipeline.

While building it, I learned about:

* SSH protocol behavior and Paramiko
* Persistent SSH host keys
* Authentication logging
* Structured event logging
* Real-time web updates using SSE
* Flask API development
* Session tracking
* Basic attack-pattern detection
* GeoIP enrichment
* Browser-side state management
* Linux firewall and SSH configuration
* Safely designing a honeypot without providing real command execution

I also encountered and fixed several practical bugs, including SSH host-key persistence, incorrect package-import checks, stale dashboard state, and command logging issues.

## Project Structure

```text
SSH-Honeypot/
│
├── honeypot.py              # Fake SSH server
├── interface.py             # Flask dashboard backend
│
├── templates/
│   └── index.html           # Web dashboard
│
├── run.sh                   # Setup and launcher script
├── requirements.txt         # Python dependencies
└── README.md                # Project documentation
```

### Runtime files

These files may be created while running the project

```text
honeypot.log
honeypot_host_key.pem
honeypot-env/
__pycache__/
```

## Disclaimer

This project is intended for **educational purposes, security research, and controlled lab environments**.

Only deploy the honeypot on systems and networks that you own or have explicit permission to monitor.
