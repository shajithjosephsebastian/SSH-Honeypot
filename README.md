# SSH Honeypot & Live Threat Dashboard

A Python SSH honeypot that logs and analyzes real attack traffic, paired
with a live web dashboard for investigating what attackers do once they
connect — credentials tried, commands run, and basic attack-pattern
detection (brute-force, dictionary, password-spray).

I built this as a hands-on way to learn how honeypots, SSH internals, and
security monitoring dashboards actually work — not as a production
security tool. See [What I learned](#what-i-learned--how-it-was-built) for
the debugging story, and [Security notes](#security-notes) for how to run
it safely.

![Dashboard overview](https://github.com/user-attachments/assets/cc34d0bf-d0aa-4d22-ad05-057ad8c980e0)

## What it does

* **Fake SSH server** ([`honeypot.py`](honeypot.py)) built on
  [Paramiko](https://www.paramiko.org/). Accepts connections on a
  configurable port, offers a list of intentionally weak decoy credentials,
  and drops anyone who guesses one into a simulated interactive shell.
  Common commands (`ls`, `whoami`, `cat /etc/passwd`, `uname -a`, etc.)
  return realistic canned output. Every connection, credential attempt,
  and command is logged.
* **Live dashboard** ([`interface.py`](interface.py) +
  [`templates/index.html`](templates/index.html)): a Flask backend that
  tails the log file, enriches each attacker's IP with GeoIP data, and
  streams events to the browser in real time over Server-Sent Events. The
  frontend is a from-scratch console (no frontend framework) that lets you:

  * See a **live threat score** and counts of detected attack patterns
  * Browse **sources** (attacking IPs) ranked by activity, with pattern
    badges (`brute-force`, `dictionary`, `pw spray`)
  * **Filter and sort** the log feed by IP, type, status, or free-text
    search, in a combined feed or a commands/auth split view
  * **Drill into a session**: every username and password an IP tried,
    every command it ran (dangerous ones flagged), and a **replay** that
    steps through its commands like a terminal recording
  * Get **toast + sound alerts** on a successful login or a burst of 5+
    failed attempts within 2 minutes
  * Copy a ready-to-run `iptables`/`fail2ban`/`ufw` command to block an IP
    (this only copies text — it never touches your firewall automatically)
  * Export logs to CSV

![Session detail drawer](https://github.com/user-attachments/assets/327eb28e-5623-4337-8b2d-64d470165902)

## Why this project

I wanted to understand, at a code level, three things that come up
constantly in security-engineering roles:

1. **How attackers actually behave** against exposed SSH — what
   credentials get tried first, how fast brute-force attempts come in,
   what commands run once someone's "in."
2. **How to build a monitoring pipeline** — structured logging, parsing,
   real-time streaming to a UI — rather than just reading about SIEM/log
   pipelines abstractly.
3. **How to reason about the security of the tool itself** — a honeypot
   that's poorly built (predictable, exploitable, or that logs real
   secrets insecurely) defeats its own purpose.

## Architecture

The project is split into three main components:

```text
                    ┌─────────────────────┐
                    │    SSH Attacker     │
                    │  Scanner / Bot /    │
                    │      Researcher     │
                    └──────────┬──────────┘
                               │
                               │ SSH
                               ▼
                    ┌─────────────────────┐
                    │     honeypot.py     │
                    │                     │
                    │  Fake SSH Server    │
                    │  Paramiko           │
                    │  Decoy Credentials  │
                    │  Simulated Shell    │
                    └──────────┬──────────┘
                               │
                               │ Structured logs
                               ▼
                    ┌─────────────────────┐
                    │    honeypot.log     │
                    │                     │
                    │ Connections         │
                    │ Auth Attempts       │
                    │ Commands            │
                    └──────────┬──────────┘
                               │
                               │ Log parsing
                               ▼
                    ┌─────────────────────┐
                    │    interface.py     │
                    │                     │
                    │ Flask API           │
                    │ Pattern Detection   │
                    │ GeoIP Enrichment    │
                    │ SSE Event Stream    │
                    └──────────┬──────────┘
                               │
                               │ HTTP / SSE
                               ▼
                    ┌─────────────────────┐
                    │   Web Dashboard     │
                    │                     │
                    │ Live Events         │
                    │ Threat Score        │
                    │ Source Analysis     │
                    │ Session Replay      │
                    │ CSV Export          │
                    └─────────────────────┘
```

### Data flow

1. An SSH client connects to the honeypot.
2. The fake SSH server records the connection and authentication attempts.
3. If a decoy credential is accepted, the attacker receives a simulated
   shell.
4. Commands are matched against predefined responses and logged.
5. The Flask backend parses the log and maintains the dashboard state.
6. New events are streamed to connected browsers using Server-Sent Events.
7. Attacker IPs can be enriched with GeoIP information.
8. The dashboard analyzes activity and identifies basic attack patterns.

## Requirements

* Python 3.8+
* No root/sudo needed with the default port (2222). See
  [Running on port 22](#running-on-port-22-optional) if you want to mimic
  a real SSH server on the standard port.

## Installation & usage

```bash
git clone https://github.com/shajithjosephsebastian/SSH-Honeypot.git
cd SSH-Honeypot
```

Easiest path — the launcher script handles the virtual environment,
dependencies, port checks, and starting both services:

```bash
./run.sh
```

Or run each piece manually:

```bash
python3 -m venv honeypot-env
source honeypot-env/bin/activate
pip install -r requirements.txt

python3 honeypot.py
python3 interface.py
```

The honeypot starts on port `2222` and the dashboard starts on:

```text
http://localhost:5000
```

Test it:

```bash
ssh -p 2222 root@localhost
```

Try a wrong password first, then try one of the intentionally accepted
decoy credentials. See `FAKE_USERS` in `honeypot.py` for the full list.

Then open `http://localhost:5000` to watch the activity appear on the
dashboard in real time.

## Running on port 22 (optional)

By default the honeypot binds to **port 2222** — a non-privileged port, so
no `sudo` is needed and it won't collide with a real SSH daemon on the same
machine.

To make it look like a real SSH server to internet traffic, change:

```python
PORT = 2222
```

to:

```python
PORT = 22
```

in `honeypot.py`.

This needs root and will conflict with any real SSH daemon on the same
host. Move the real SSH daemon to a different port first, or run the
honeypot on an isolated/dedicated machine.

## Decoy credentials

A fixed list of common weak username/password pairs
(`root:password123`, `admin:admin123`, `pi:raspberry`, etc.) lives in
`FAKE_USERS` at the top of `honeypot.py`.

Edit this list to add, remove, or change what the honeypot "accepts."

These credentials are intentionally fake and should never be reused as
real passwords.

## Attack pattern detection

The dashboard performs basic behavioral analysis of incoming activity.

### Brute-force

Detects repeated failed authentication attempts from the same source,
particularly when attempts occur within a short time window.

### Dictionary attack

Identifies repeated authentication attempts involving multiple common
username/password combinations.

### Password spray

Looks for authentication behavior where a source attempts a small number
of passwords across multiple usernames rather than repeatedly targeting a
single account.

These detections are intentionally simple and are designed for learning
and visualization rather than production-grade intrusion detection.

## Live monitoring

The dashboard uses **Server-Sent Events (SSE)** to stream new honeypot
events to the browser without requiring a full page refresh.

This allows the dashboard to display:

* New connections
* Authentication attempts
* Successful logins
* Commands executed inside simulated sessions
* Dangerous command indicators
* Attack-pattern detections
* Threat-score changes

The dashboard also maintains session history so an individual attacker
can be investigated after the initial connection.

![Additional dashboard view](https://github.com/user-attachments/assets/cb0abae0-a078-444b-a9d4-bc9854f38a87)

## Web dashboard API

| Endpoint                     | Description                                                                                       |
| ---------------------------- | ------------------------------------------------------------------------------------------------- |
| `GET /api/logs`              | Recent log entries. Supports `limit`, `filter`, `type`, `status`, `ip` query params.              |
| `GET /api/stats`             | Summary counters (total attempts, unique IPs, top usernames, etc).                                |
| `GET /api/patterns`          | Attack pattern analysis (brute-force/dictionary/spray detection, geo distribution, attack score). |
| `GET /api/geo/<ip>`          | GeoIP lookup for a specific IP.                                                                   |
| `GET /api/stream`            | Server-Sent Events stream of new log entries.                                                     |
| `GET /api/export?format=csv` | Export logs as CSV.                                                                               |
| `GET /api/clear-cache`       | Clears the server's in-memory log cache (does not touch `honeypot.log` on disk).                  |

## What I learned / how it was built

This started as a fairly simple fake-SSH-server script and grew into a
small monitoring pipeline. A few real bugs I ran into and fixed along the
way, because they were genuinely instructive:

* **The host SSH key wasn't actually persisting.** I was saving it with
  `str(key)`, which — I learned the hard way — returns the *public* key
  blob in Paramiko, not something you can reload as a private key. The
  honeypot silently generated a brand-new host key on every restart,
  which would make any real SSH client complain about the host key
  changing. Fixed with `key.write_private_key_file(...)`.
* **A "DANGEROUS" marker was leaking into logged command text.** I
  tagged dangerous commands (`rm`, `wget`, etc.) by appending a suffix to
  the same string that got logged and parsed back out — so `rm -rf /`
  came back out of the log as `rm -rf / DANGEROUS`, corrupting the stored
  command. Separated the console-only marker from the persisted log line.
* **The dashboard's cached state could go stale.** Local browser storage
  (so a page refresh doesn't lose your session) could disagree with the
  server's log file if it was ever cleared or rotated outside the
  dashboard — the UI kept showing attackers the server had already
  forgotten about. Added a reconciliation check: if cached history shares
  no IDs with what the server currently reports, treat the cache as stale
  and drop it.
* **Dependency-check false positives in the launcher script.** `run.sh`
  checked for installed packages by importing the PyPI package name
  directly (`import Flask`), which doesn't match the real importable
  module name (`flask`) — so it kept reporting installed packages as
  missing and reinstalling them on every launch.

## Security notes

**Run the honeypot as an isolated system.**

* Run it on a sandboxed VM, container, or dedicated box.
* Never run it on a machine containing sensitive data.
* Do not expose the Flask dashboard directly to the public internet.
* Restrict dashboard access with a firewall or bind it to localhost.
* Treat all captured attacker input as untrusted data.
* Do not use the decoy credentials anywhere outside the honeypot.

### No real command execution

Attackers get a fake shell, not real code execution.

Commands are matched against a fixed list of canned responses. Anything
unrecognized returns `command not found`.

There is no real shell or system command interpreter behind the SSH session.

### GeoIP privacy/network considerations

GeoIP lookups call the external, unauthenticated
[ip-api.com](https://ip-api.com) API for every new IP seen.

Be aware that this creates outbound network traffic and sends attacker IP
addresses to an external service. This may be undesirable in
network-restricted environments.

### Firewall safety

The dashboard can generate commands such as:

```text
iptables
fail2ban
ufw
```

These are only copied to the clipboard for the operator.

**The application never automatically modifies the host firewall.**

### Sensitive files

The following files should never be committed to Git:

```text
honeypot.log
*.key
*.pem
*.pub
.env
honeypot-env/
__pycache__/
```

Make sure they are covered by `.gitignore`.

## Project structure

```text
SSH-Honeypot/
│
├── honeypot.py                 # Fake SSH server
├── interface.py                # Flask dashboard backend
│
├── templates/
│   └── index.html              # Dashboard UI
│
├── docs/
│   ├── screenshot-dashboard.png
│   ├── screenshot-session.png
│   └── demo.gif
│
├── run.sh                      # Setup and launcher script
├── requirements.txt            # Python dependencies
├── .gitignore                  # Ignored files and secrets
└── README.md                   # Project documentation
```

### Runtime files

Some files are created while the honeypot is running but should not be
committed to the repository:

```text
honeypot.log                  # Attack/event log
honeypot_host_key.pem         # Persistent SSH host private key
honeypot-env/                 # Python virtual environment
__pycache__/                  # Python bytecode cache
```

These should be included in `.gitignore`.

## Future improvements

Some areas I would like to explore next:

* More sophisticated attack-pattern detection
* Better session correlation across reconnects
* Persistent storage using SQLite or PostgreSQL
* Additional protocol honeypots
* Authentication anomaly scoring
* Interactive attack timelines
* More detailed GeoIP visualization
* Docker-based isolated deployment
* Automated log rotation and retention
* Integration with a SIEM such as Splunk, Wazuh, or Elastic
* Additional alerting integrations

## Disclaimer

This project is intended for **educational purposes, security research,
and controlled lab environments**.

Do not deploy it on systems or networks where you do not have permission
to monitor incoming activity. Running an internet-facing honeypot carries
security and privacy risks; isolate it appropriately and understand the
traffic and data it will collect.
