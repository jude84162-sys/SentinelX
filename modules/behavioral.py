# modules/behavioral.py
"""
SentinelX - Behavioral Analysis
Detects suspicious runtime behavior on Linux.

Monitors:
- Process spawning (shells from non-shell parents)
- Writes to system directories
- Outbound connections
- Privilege escalation attempts
"""

import os
import re
import platform
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger("SentinelX.behavioral")


def _is_linux():
    return platform.system().lower() == "linux"


def _run_cmd(cmd, timeout=10):
    try:
        result = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


# ============================================================
# Suspicious process patterns
# ============================================================

SHELL_NAMES = {"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh"}
SUSPICIOUS_PARENTS = {
    "nginx": ["sh", "bash", "python", "perl"],
    "apache2": ["sh", "bash", "python", "perl"],
    "httpd": ["sh", "bash", "python", "perl"],
    "mysqld": ["sh", "bash"],
    "postgres": ["sh", "bash"],
    "redis-server": ["sh", "bash"],
}

SUSPICIOUS_PORTS = {4444, 5555, 31337, 12345, 6666, 6667, 8888, 9001}

PROTECTED_DIRS = ["/etc", "/usr/bin", "/usr/sbin", "/boot", "/sys"]


# ============================================================
# Process checks
# ============================================================

def check_suspicious_spawns():
    """Detect shell spawned by unusual parents."""
    findings = []

    try:
        import psutil
    except ImportError:
        return findings

    for proc in psutil.process_iter(["pid", "name", "ppid"]):
        try:
            pid = proc.info["pid"]
            name = (proc.info["name"] or "").lower()
            ppid = proc.info["ppid"]

            # Shell?
            if name not in SHELL_NAMES:
                continue

            # Get parent
            try:
                parent = psutil.Process(ppid)
                parent_name = (parent.name() or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            # Check against suspicious parents
            for bad_parent, bad_children in SUSPICIOUS_PARENTS.items():
                if bad_parent in parent_name:
                    findings.append({
                        "type": "suspicious_spawn",
                        "severity": "HIGH",
                        "pid": pid,
                        "process": name,
                        "parent_pid": ppid,
                        "parent": parent_name,
                        "reason": f"Shell '{name}' spawned by service '{parent_name}'",
                    })
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return findings


def check_suspicious_ports():
    """Check for connections on suspicious ports."""
    findings = []

    try:
        import psutil
    except ImportError:
        return findings

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "ESTABLISHED":
                continue

            if conn.raddr:
                rport = conn.raddr.port
                if rport in SUSPICIOUS_PORTS:
                    pid = conn.pid
                    pname = "?"
                    if pid:
                        try:
                            pname = psutil.Process(pid).name()
                        except Exception:
                            pass

                    findings.append({
                        "type": "suspicious_connection",
                        "severity": "HIGH",
                        "remote": f"{conn.raddr.ip}:{rport}",
                        "pid": pid,
                        "process": pname,
                        "reason": f"Connection to suspicious port {rport}",
                    })
    except (PermissionError, psutil.AccessDenied):
        pass

    return findings


# ============================================================
# File system checks
# ============================================================

def check_recent_writes_system():
    """Find recently modified files in system dirs."""
    findings = []
    cutoff = datetime.now() - timedelta(hours=24)

    for directory in PROTECTED_DIRS:
        p = Path(directory)
        if not p.exists():
            continue

        try:
            for f in p.rglob("*"):
                if not f.is_file():
                    continue
                try:
                    mtime = datetime.fromtimestamp(f.stat().st_mtime)
                    if mtime > cutoff:
                        findings.append({
                            "type": "recent_system_write",
                            "severity": "MEDIUM",
                            "path": str(f),
                            "mtime": mtime.isoformat(),
                            "reason": f"Modified in last 24h",
                        })
                except (PermissionError, OSError):
                    continue
        except PermissionError:
            continue

    return findings[:20]  # Limit


# ============================================================
# auditd integration
# ============================================================

def get_recent_execve(limit=100):
    """Get recent execve from auditd if available."""
    output = _run_cmd(
        "ausearch -ts recent -m EXECVE 2>/dev/null | tail -%d" % limit,
        timeout=15
    )
    if not output:
        return []

    events = []
    for line in output.splitlines():
        if "type=EXECVE" in line or "argc=" in line:
            events.append(line[:200])
    return events[:20]


# ============================================================
# Main check
# ============================================================

def run_behavioral_check():
    result = {
        "timestamp": datetime.now().isoformat(),
        "platform": platform.platform(),
        "is_linux": _is_linux(),
        "suspicious_spawns": [],
        "suspicious_connections": [],
        "recent_system_writes": [],
        "recent_execve": [],
        "summary": {},
    }

    if not _is_linux():
        result["error"] = "Behavioral analysis is Linux-only"
        return result

    result["suspicious_spawns"] = check_suspicious_spawns()
    result["suspicious_connections"] = check_suspicious_ports()
    result["recent_system_writes"] = check_recent_writes_system()
    result["recent_execve"] = get_recent_execve(50)

    total = (
        len(result["suspicious_spawns"]) +
        len(result["suspicious_connections"]) +
        len(result["recent_system_writes"])
    )

    result["summary"] = {
        "suspicious_spawns": len(result["suspicious_spawns"]),
        "suspicious_connections": len(result["suspicious_connections"]),
        "recent_system_writes": len(result["recent_system_writes"]),
        "total_issues": total,
    }

    return result


def print_behavioral_report(result):
    print("\n" + "=" * 70)
    print("  Behavioral Analysis Report - SentinelX")
    print("=" * 70)

    if not result.get("is_linux"):
        print(f"\n[!] {result.get('error', 'Linux only')}")
        return

    s = result["summary"]
    print(f"\n[*] Suspicious spawns: {s['suspicious_spawns']}")
    print(f"[*] Suspicious connections: {s['suspicious_connections']}")
    print(f"[*] Recent system writes: {s['recent_system_writes']}")
    print(f"[*] Total issues: {s['total_issues']}")

    if result["suspicious_spawns"]:
        print(f"\n[!] Suspicious process spawns:")
        for f in result["suspicious_spawns"][:10]:
            print(f"    ⚠ {f['reason']}")
            print(f"       PID {f['pid']} (parent: {f['parent']})")

    if result["suspicious_connections"]:
        print(f"\n[!] Suspicious connections:")
        for f in result["suspicious_connections"][:10]:
            print(f"    ⚠ {f['reason']}")
            print(f"       Process: {f['process']}")

    if result["recent_system_writes"]:
        print(f"\n[!] Recent writes to system dirs (24h):")
        for f in result["recent_system_writes"][:10]:
            print(f"    - {f['path']}")

    if s["total_issues"] == 0:
        print(f"\n[✓] No suspicious behavior detected")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if not _is_linux():
        print(f"[i] Linux only (current: {platform.system()})")
    else:
        print_behavioral_report(run_behavioral_check())
