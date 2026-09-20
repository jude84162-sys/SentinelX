<div align="center">

# 🛡️ SentinelX

**Modular Enterprise Blue Team Suite**
[![Tests](https://github.com/jude84162-sys/SentinelX/actions/workflows/test.yml/badge.svg)](https://github.com/jude84162-sys/SentinelX/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/jude84162-sys/SentinelX)](https://github.com/jude84162-sys/SentinelX/releases)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Android%20%7C%20Linux%20%7C%20macOS%20%7C%20Windows-green.svg)]()
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/jude84162-sys/SentinelX?style=social)](https://github.com/jude84162-sys/SentinelX/stargazers)

*Cross-platform security triage for Android, Termux, WSL, Kali, and Linux*

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776ab?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20Linux%20%7C%20macOS%20%7C%20WSL-4caf50?logo=linux&logoColor=white)]()
[![Docker](https://img.shields.io/badge/Docker-jude84162%2Fsentinelx-2496ed?logo=docker&logoColor=white)](https://hub.docker.com/r/jude84162/sentinelx)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-blue.svg)](https://github.com/jude84162-sys/SentinelX/pulls)

*A lightweight, modular, and portable incident response framework designed for security professionals, red/blue teamers, and privacy-conscious users.*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Modules](#-modules) • [Platform Matrix](#-platform-support-matrix) • [Contributing](#-contributing)

</div>

---

## 📖 Overview

**SentinelX** is a comprehensive, cross-platform security triage suite that unifies system forensics, network analysis, Android OSINT, and threat detection into a single, cohesive framework.

Built from the ground up to work seamlessly across **Android (Termux)**, **WSL**, **Kali Linux**, **macOS**, and any Linux distribution — SentinelX detects its runtime environment and adapts its capabilities automatically.

Whether you're performing rapid incident response on a compromised endpoint, auditing your own phone for spyware, or conducting OSINT on suspicious phone numbers — SentinelX delivers actionable results in seconds.

---

## ✨ Features

### 🔍 Core Triage Modules

- **Process Analysis** — Enumerate running processes, detect suspicious binaries, flag high CPU/memory consumers, identify execution from temporary paths
- **Network Inspection** — Full TCP/UDP connection table with PID attribution, listening port enumeration, established connection tracking, and suspicious port detection (`4444`, `31337`, `5555`, etc.)
- **File System Triage** — Smart heuristics to find malicious files while aggressively reducing false positives through whitelisting and path-aware context
- **Persistence Detection** — Discover startup scripts, cron jobs, systemd services, `rc.local`, and shell profile hijacking

### 📱 Android-Specific Modules

- **Package OSINT** — Enumerate all installed apps using `cmd package` (bypasses Android 11+ package visibility restrictions **without root**)
- **Permission Analysis** — Classify dangerous and critical permissions per app, generate risk scores
- **Network Triage** — WiFi SSID/BSSID/DNS analysis, evil-twin detection, telephony info via Termux:API
- **Spyware Detection** — Scan SMS inbox, call logs, contacts, and clipboard for surveillance indicators (premium-rate numbers, phishing keywords, sensitive data leakage)

### 🌐 Desktop-Only Modules

- **Phone Number OSINT** — Analyze international phone numbers: country, carrier, timezone, line type (mobile/VoIP/premium), and dynamic risk scoring
- **Native Notifications** — Desktop alerts via `notify-send` (Linux), `osascript` (macOS), or Windows toast (WSL)

### 📊 Reporting

- **Structured JSON** output for automation and pipelines
- **Rich HTML Dashboard** with dark theme, severity badges, and interactive tables (offline-capable, single-file)

### 🔍 IOC Hunter (Malware Hash Detection)

Detects known malware using SHA-256 hash signatures.

**Data sources:**
- **MalwareBazaar** — 1800+ recent malware samples (auto-updated)
- **Local database** — user-defined hashes
- **Built-in** — EICAR, WannaCry, NotPetya

**Features:**
- Works from geo-blocked regions (uses export files, not APIs)
- 6-hour cache TTL for online hashes
- 100MB file size limit (skips larger)
- Duplicate detection via realpath

**Usage:**
```bash
# Scan a single file
python SentinelX.py --ioc ~/suspicious.exe

# Scan a directory
python SentinelX.py --ioc ~/Downloads

# Automatic (runs as part of --triage-all)
python SentinelX.py --triage-all

---

## 🎯 Why SentinelX?

| Advantage | Description |
|-----------|-------------|
| 🚀 **Zero-Config** | Auto-detects Termux, WSL, Kali, Linux, macOS — no manual setup |
| 📱 **Root-Free Android** | Enumerates apps on Android 11+ using `cmd` IPC channel |
| 🧩 **Modular** | Run only what you need — each module works independently |
| 🛡️ **Graceful Degradation** | Blocked modules report cleanly instead of crashing |
| 🎨 **Professional Reports** | JSON + HTML with severity classification |
| 📦 **Lightweight** | Pure Python, minimal dependencies |
| 🔓 **Open Source** | MIT licensed, fully auditable |

---

## 📦 Installation

## 🚀 Quick Install

**One-line install (recommended):**

```bash
curl -sSL https://raw.githubusercontent.com/jude84162-sys/SentinelX/main/install.sh | bash
source ~/.bashrc
sentinelx --triage-all
### Prerequisites

- **Python 3.8+**
- **pip** (Python package manager)
- **Git** (for cloning)

### 1. Clone the Repository

```bash
git clone https://github.com/jude84162-sys/SentinelX.git
cd SentinelX
```

2. Install Python Dependencies

```bash
pip install psutil phonenumbers
```

On some systems with PEP 668 enforcement (Debian 12+, Kali), use:

```bash
pip install --break-system-packages psutil phonenumbers
```

Or install via system package manager:

```bash
# Debian / Ubuntu / Kali
sudo apt install python3-psutil python3-phonenumbers
```

3. Android (Termux) — Additional Setup

```bash
# Install Termux:API CLI
pkg install termux-api

# Verify installation
termux-battery-status
```

Then install the Termux:API companion app from F-Droid and grant all permissions (SMS, Calls, Contacts, Location, Storage, Camera, Microphone, Notifications).

4. 🐳 Docker (WSL / Kali / Linux / macOS)

Skip Python setup entirely — run SentinelX in a container.

Quick Start

```bash
# Pull the official image
docker pull jude84162/sentinelx:latest

# Run full triage (reports saved to ./outputs)
docker run --rm -v $(pwd)/outputs:/app/outputs jude84162/sentinelx
```

Common Commands

```bash
# Show environment info
docker run --rm jude84162/sentinelx --env

# Process analysis only
docker run --rm jude84162/sentinelx --process

# Network analysis
docker run --rm jude84162/sentinelx --network

# File system triage
docker run --rm jude84162/sentinelx --files

# Persistence detection
docker run --rm jude84162/sentinelx --persistence

# Phone OSINT
docker run --rm jude84162/sentinelx --phone +963912345678

# Persist reports to host
docker run --rm -v $(pwd)/outputs:/app/outputs jude84162/sentinelx --triage-all
```

Build Locally

```bash
git clone https://github.com/jude84162-sys/SentinelX.git
cd SentinelX
docker build -t sentinelx .
docker run --rm sentinelx --triage-all
```

Docker Hub

Image: jude84162/sentinelx

```bash
docker pull jude84162/sentinelx:latest
docker pull jude84162/sentinelx:1.0.0
```

Note: Docker containers cannot access Android's IPC layer, so Android-specific modules are unavailable. Use the Termux installation for Android triage.

---

🚀 Usage

Show Environment Info

```bash
python SentinelX.py --env
```

Displays detected platform, available modules, and capability matrix.

Full Triage (All Modules)

```bash
python SentinelX.py --triage-all
```

Runs every applicable module for the current platform, prints results to console, and saves both JSON and HTML reports.

Run Individual Modules

```bash
# Core modules
python SentinelX.py --process           # Process analysis
python SentinelX.py --network           # Network connections
python SentinelX.py --files             # File system scan
python SentinelX.py --persistence       # Persistence mechanisms

# Android-only
python SentinelX.py --android           # Package OSINT
python SentinelX.py --android-network   # WiFi/telephony
python SentinelX.py --spyware           # SMS/calls/clipboard

# Desktop-only
python SentinelX.py --phone +963912345678

# Utilities
python SentinelX.py --notify-test       # Test notifications
python SentinelX.py --version           # Show version
```

---

🧩 Modules

<details>
<summary><strong>⚙️ Process Analysis</strong> (<code>modules/process.py</code>)</summary>

Enumerates running processes with:

· PID, name, user, status, CPU%, memory%, command line
· Suspicious binary detection (nc, nmap, meterpreter, xmrig, etc.)
· High CPU (>50%) and memory (>20%) flagging
· Execution from temporary paths (/tmp, /dev/shm, /data/local/tmp)

</details>

<details>
<summary><strong>🌐 Network Analysis</strong> (<code>modules/network.py</code>)</summary>

Full psutil-based network inspection:

· TCP/UDP connection table with process attribution
· Listening port enumeration
· Established connection tracking
· Suspicious port detection (4444, 5555, 31337, 12345, 6666, 6667)
· Graceful fallback to ss / netstat when psutil is blocked

Note: On Android, /proc/net/tcp is restricted — the module reports this cleanly and suggests the Android Network module instead.

</details>

<details>
<summary><strong>📁 File System Triage</strong> (<code>modules/files.py</code>)</summary>

Context-aware file scanning:

· High-risk extensions (.sh, .elf, .dex, .so, .pl, .rb, .bin)
· Medium-risk extensions (.apk, .exe, .msi, .jar, .js)
· Red-flag filenames (payload, exploit, backdoor, meterpreter, xmrig)
· Whitelisting of trusted paths (/usr/lib, ~/go/pkg, .cache, etc.)
· Home dotfile exclusions (.bashrc, .env, .gitconfig are NOT flagged)
· Build/cache directory skipping (node_modules, site-packages, __pycache__)

</details>

<details>
<summary><strong>🔗 Persistence Detection</strong> (<code>modules/persistence.py</code>)</summary>

Discovers persistence mechanisms:

· Shell startup files (.bashrc, .profile, .zshrc)
· User and system cron jobs (crontab -l, /etc/cron.*)
· systemd user services (~/.config/systemd/user/*.service)
· rc.local inspection
· Termux $PREFIX/etc/profile.d/ scripts
· Content analysis for suspicious patterns (curl, wget, nc, /dev/tcp/, bash -i)

</details>

<details>
<summary><strong>📱 Android OSINT</strong> (<code>modules/android_osint.py</code>)</summary>

Package enumeration and analysis:

· Method 1: cmd package list packages -3 — works on Android 11+ without root
· Method 2: pm list packages -3 — fallback
· Method 3: dumpsys package packages — when available
· Method 4: /sdcard/Android/data filesystem enumeration

Analysis:

· Known-safe package whitelist (Termux, Chrome, WhatsApp, etc.)
· Modified/cracked app detection (snaptube, vanced, gbwhatsapp)
· Suspicious keyword matching (spy, keylog, steal, track, monitor)
· Dangerous/critical permission classification
· Risk scoring per app

</details>

<details>
<summary><strong>📡 Android Network</strong> (<code>modules/network_android.py</code>)</summary>

Termux:API-powered network introspection:

· Current WiFi SSID, BSSID, link speed, DNS servers
· Nearby network scan with evil-twin detection
· Telephony info (carrier, country, SIM state)
· Public IP lookup
· DNS anomaly detection (non-standard resolvers)

</details>

<details>
<summary><strong>🕵️ Android Spyware Detection</strong> (<code>modules/android_spyware.py</code>)</summary>

Surveillance indicator scan:

· SMS inbox (200 messages) — phishing keywords, OTP prompts, premium numbers
· Call log (100 calls) — premium-rate numbers, short-duration beacons
· Contacts enumeration
· Clipboard analysis — crypto addresses, passwords, base64 payloads

</details>

<details>
<summary><strong>☎️ Phone Number OSINT</strong> (<code>modules/phone_osint.py</code>)</summary>

International number analysis (desktop only):

· Country, region, carrier, timezone
· Line type (mobile, fixed, VoIP, premium, toll-free)
· Formatting (E.164, International, National)
· Risk scoring:
  · Premium-rate prefixes (+1900, +449, etc.)
  · High-risk country codes
  · VoIP carrier detection
  · Disposable/virtual number patterns
· Manual lookup suggestions (Truecaller, HIBP, WhatsApp)

</details>

<details>
<summary><strong>🔔 Notifications</strong> (<code>modules/notify.py</code>, <code>modules/desktop_notify.py</code>)</summary>

Native alerts on any platform:

· Android: Termux:API toast, notification, vibration, TTS
· Linux: notify-send or zenity
· macOS: osascript
· WSL: PowerShell bridge to Windows toast
· Auto-summarizes findings and alerts on HIGH/CRITICAL severity

</details>

<details>
<summary><strong>📊 HTML Dashboard</strong> (<code>modules/html_report.py</code>)</summary>

Self-contained dark-themed dashboard:

· Severity badges (Critical/High/Medium/Low)
· Stats cards per module
· Sortable tables
· Finding details with color-coded borders
· Fully offline — single HTML file, no external dependencies

</details>

---

📊 Platform Support Matrix

Module Termux (Android) Docker WSL / Kali / Linux macOS
Process Triage ⚠️ Partial ✅ ✅ Full ✅ Full
Network (psutil) ❌ Blocked ✅ ✅ Full ✅ Full
File Triage ✅ ✅ ✅ Full ✅ Full
Persistence ✅ Termux ✅ ✅ systemd + cron ⚠️ Partial
Android OSINT ✅ ❌ ⏭️ N/A ⏭️ N/A
Android Network ✅ Termux:API ❌ ⏭️ N/A ⏭️ N/A
Android Spyware ✅ Termux:API ❌ ⏭️ N/A ⏭️ N/A
Phone OSINT ⚠️ Optional ✅ ✅ ✅
Notifications ✅ Termux:API ⚠️ ✅ notify-send ✅ osascript
HTML Dashboard ✅ ✅ ✅ ✅

---

📁 Project Structure

```
SentinelX/
├── SentinelX.py              # Main CLI entry point
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── LICENSE                   # MIT License
├── Dockerfile                # Docker image build
├── .dockerignore             # Docker build exclusions
├── .gitignore                # Git exclusions
│
├── modules/
│   ├── __init__.py           # Package marker
│   ├── env_detect.py         # Environment detection
│   ├── process.py            # Process analysis
│   ├── network.py            # Network (psutil)
│   ├── network_android.py    # Android network (Termux:API)
│   ├── files.py              # File system triage
│   ├── persistence.py        # Persistence detection
│   ├── android_osint.py      # Android package analysis
│   ├── android_spyware.py    # SMS/calls/clipboard scan
│   ├── notify.py             # Android notifications
│   ├── desktop_notify.py     # Desktop notifications
│   ├── phone_osint.py        # Phone number OSINT
│   └── html_report.py        # HTML dashboard generator
│
└── outputs/                  # Generated reports (gitignored)
    ├── full_triage_report.json
    └── full_triage_report.html
```

---

🛠️ Requirements

Dependency Purpose Required
Python 3.8+ Runtime ✅
psutil Process & network analysis ✅
phonenumbers Phone OSINT Optional
termux-api Android SMS/calls/WiFi/notifications Android only
Docker Containerized deployment Optional

---

🔐 Security & Privacy

· No data leaves your device — all analysis is local
· No network calls except optional public IP lookup (ipify.org)
· No telemetry, no analytics, no phoning home
· Open source — audit every line of code
· Reports are stored locally in outputs/ (gitignored)

---

🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (git checkout -b feature/amazing-module)
3. Commit your changes (git commit -m 'Add amazing module')
4. Push to the branch (git push origin feature/amazing-module)
5. Open a Pull Request

Development Guidelines

· Follow PEP 8 style conventions
· Add docstrings to all public functions
· Test on at least two platforms before submitting
· Update README if adding a new module

---

⚠️ Disclaimer

SentinelX is intended for authorized security testing and personal device monitoring only.

· ✅ Use on devices you own
· ✅ Use on systems you have explicit written permission to test
· ✅ Use for defensive blue team purposes
· ❌ Do NOT use for unauthorized surveillance
· ❌ Do NOT use on devices belonging to others without consent

The authors assume no liability for misuse or damage caused by this tool.

---

📜 License

This project is licensed under the MIT License — see the LICENSE file for details.

---

🙏 Acknowledgments

· psutil — System and process utilities
· phonenumbers — Phone number parsing
· Termux — Android terminal emulator
· The open-source security community

---

<div align="center">

Built with 🛡️ for defenders, by jude84162-sys

⭐ Star this repo if you find it useful! ⭐

</div>