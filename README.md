# Simple SSH Honeypot

A lightweight SSH honeypot written in Python. It presents a fake SSH server
that accepts a set of decoy credentials, drops attackers into a simulated
shell, and logs everything — connections, credential attempts, and commands
run — for later analysis. A companion Flask web dashboard visualizes the
logs in real time, including GeoIP lookups and basic brute-force/dictionary/
password-spray detection.

> ⚠️ **This is a research/monitoring tool, not a production security
> product.** Only deploy it on systems and networks you own or are
> authorized to monitor. See [Security notes](#security-notes) below.

## How it works

- **`honeypot.py`** — a fake SSH server built on [Paramiko](https://www.paramiko.org/).
  It accepts connections, offers a list of intentionally weak decoy
  credentials (see `FAKE_USERS` in the script), and lets anyone who guesses
  one of them "log in" to a fake interactive shell. Common commands
  (`ls`, `whoami`, `cat /etc/passwd`, `uname -a`, etc.) return realistic
  canned output; anything else returns `command not found`. Every
  connection, login attempt, and command is written to `honeypot.log`
  (rotated automatically at 10MB, 5 backups kept).
- **`interface.py`** — a Flask web app that tails `honeypot.log`, parses it
  into structured events, and serves a live dashboard (`templates/index.html`)
  over Server-Sent Events. It adds GeoIP lookups (via the free
  [ip-api.com](https://ip-api.com) API), tracks stats (unique IPs, top
  usernames/passwords, success/fail counts), and flags likely brute-force,
  dictionary, or password-spray attacks. It also exposes a small JSON API
  and CSV/JSON export.
- **`run.sh`** — an interactive launcher that sets up a virtual environment,
  installs dependencies, and starts/stops/monitors both services.
- **`fix_network.sh`** — a simpler helper that just kills any existing
  honeypot/interface processes and restarts both in the background.

## Requirements

- Python 3.8+
- Root/sudo privileges **only if** you bind the honeypot to port 22 (see
  [Choosing a port](#choosing-a-port) below)

## Installation

```bash
git clone https://github.com/shajithjosephsebastian/Simple-ssh-honeypot.git
cd Simple-ssh-honeypot

python3 -m venv honeypot-env
source honeypot-env/bin/activate

pip install -r requirements.txt
```

Or simply run `./run.sh`, which does all of the above for you and gives you
a menu to start/stop/monitor the services.

## Usage

**Start the honeypot:**

```bash
python3 honeypot.py
```

By default the honeypot listens on **port 2222**, a non-privileged port,
so no `sudo`/root is needed. A host RSA key (`host_rsa_key`) is generated
automatically on first run if one doesn't already exist.

Test it with:

```bash
ssh -p 2222 root@localhost
# password: password123   (see FAKE_USERS in honeypot.py for the full list)
```

**Start the web dashboard** (in a separate terminal):

```bash
python3 interface.py
```

The dashboard is served at **http://localhost:5000**.

**Or use the launcher for both at once:**

```bash
./run.sh
```

### Using port 22 instead

If you want the honeypot to look like a real SSH server to internet
traffic, change the port back to 22:

```python
# honeypot.py
PORT = 22
```

This requires running with `sudo` (22 is a privileged port on Linux) and
will conflict with any real SSH daemon on the same host — move the real
one to a different port first, or run the honeypot on a dedicated/isolated
host.

## Decoy credentials

The honeypot accepts a fixed list of common weak username/password
combinations (e.g. `root:password123`, `admin:admin123`, `pi:raspberry`).
The full list is in `FAKE_USERS` at the top of `honeypot.py` — edit it to
add, remove, or change credentials.

## Logs

- `honeypot.log` — plain-text, human-readable log of every connection,
  auth attempt, and command (rotated at 10MB × 5 backups).
- The web dashboard re-parses this file continuously, so you don't need a
  separate structured log format — just tail `honeypot.log` if you want
  raw output, or use the dashboard/API for structured/filterable data.

## Dashboard features

The dashboard (`templates/index.html`) is an operator console built around
the attacking IP as the unit of investigation, not a flat log feed:

- **Source table** — every attacking IP, grouped and sorted by attempts,
  commands run, or recency. Each row shows a live-computed pattern badge:
  `brute-force`, `pw spray`, `dictionary`, or `probe`.
- **Live feed / map toggle** — a real-time event ticker (with search) or a
  world map plotting attacker locations by lat/lon (from the GeoIP data),
  sized by attempt count and colored red if that IP has breached.
- **Session detail drawer** — click any IP to see everything it did: every
  username and password tried, every command run (dangerous ones like
  `rm`, `wget`, `chmod 777` are flagged), first/last seen, geo and ISP.
- **Session replay** — replays a selected attacker's commands one at a
  time in a terminal-style view, so you can watch what they did in order.
- **Block-IP helper** — copies a ready-to-run `iptables` / `fail2ban` /
  `ufw` command for that IP to your clipboard. This does **not** modify
  your firewall automatically — it's a copy-paste convenience; you review
  and run the command yourself.
- **Alerts** — a toast notification (plus a short beep and, if you grant
  permission, a browser notification) fires when:
  - any IP successfully authenticates (a "breach"), or
  - any IP racks up 5+ failed logins within a 2-minute window.
- **Persistence** — session data (the log feed, per-IP aggregates) is
  cached in the browser's `localStorage`, so refreshing the dashboard
  doesn't lose what's been observed; it re-syncs with `honeypot.log` on
  load and merges the two.
- **CSV export** and a **pause** toggle for the live stream are in the top
  bar.

## Web dashboard API

| Endpoint | Description |
|---|---|
| `GET /api/logs` | Recent log entries. Supports `limit`, `filter`, `type`, `status`, `ip` query params. |
| `GET /api/stats` | Summary counters (total attempts, unique IPs, top usernames, etc). |
| `GET /api/patterns` | Attack pattern analysis (brute-force/dictionary/spray detection, geo distribution, attack score). |
| `GET /api/geo/<ip>` | GeoIP lookup for a specific IP. |
| `GET /api/stream` | Server-Sent Events stream of new log entries. |
| `GET /api/export?format=csv\|json` | Export logs. |
| `GET /api/clear` | Clear the in-memory log cache (does not delete `honeypot.log`). |

## Security notes

- **Isolate it.** Run this on a sandboxed VM, container, or dedicated box —
  never on a machine with anything sensitive on it. The whole point is to
  look attackable.
- **Attackers get a fake shell, not real code execution.** Commands are
  matched against a fixed list of canned responses in `honeypot.py`
  (`get_fake_response`); anything not recognized returns
  `command not found`. There's no real shell, filesystem, or interpreter
  behind it.
- **The GeoIP lookup calls an external, unauthenticated API** (ip-api.com)
  for every new IP seen. Be aware of that outbound traffic and its rate
  limits if you're running this somewhere network-restricted.
- **`host_rsa_key` is generated locally and gitignored.** Don't commit real
  private keys to version control.
- Consider firewalling the web dashboard (`interface.py`, port 5000) so
  it's only reachable by you, not the public internet.

## Project structure

```
Simple-ssh-honeypot/
├── honeypot.py          # Fake SSH server (Paramiko)
├── interface.py         # Flask web dashboard
├── templates/
│   └── index.html       # Dashboard UI
├── run.sh               # Interactive setup/launcher script
├── fix_network.sh       # Quick restart helper
├── requirements.txt
└── README.md
```

## License

[MIT](LICENSE) — see the LICENSE file for details.
