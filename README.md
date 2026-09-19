<div align="center">

# 🛡️ SentinelX

**Modular Enterprise Blue Team Suite**

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

### Prerequisites

- **Python 3.8+**
- **pip** (Python package manager)
- **Git** (for cloning)

### 1. Clone the Repository

```bash
git clone https://github.com/jude84162-sys/SentinelX.git
cd SentinelX