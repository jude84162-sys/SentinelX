# modules/process.py
"""
SentinelX - Process Analysis Module
Full error handling for Android/Termux environments.
"""

import psutil
import platform
import logging
from datetime import datetime

logger = logging.getLogger("SentinelX.process")


def _is_android():
    return "android" in platform.platform().lower()


def run_process_triage():
    """
    Analyze running processes with full error handling.
    """
    result = {
        "timestamp": datetime.now().isoformat(),
        "platform": platform.platform(),
        "is_android": _is_android(),
        "processes": [],
        "suspicious": [],
        "high_cpu": [],
        "high_memory": [],
        "summary": {},
        "error": None,
        "warning": None
    }

    try:
        procs = list(psutil.process_iter([
            'pid', 'name', 'username', 'status',
            'cpu_percent', 'memory_percent', 'cmdline'
        ]))
    except PermissionError as e:
        result["error"] = f"Permission denied: {e}"
        result["warning"] = (
            "Android restricts access to process information. "
            "Full access requires root."
        )
        return result
    except Exception as e:
        result["error"] = f"Error: {e}"
        return result

    for proc in procs:
        try:
            info = proc.info
            cmdline = info.get('cmdline') or []
            entry = {
                "pid": info.get('pid'),
                "name": info.get('name') or "?",
                "user": info.get('username') or "?",
                "status": info.get('status') or "?",
                "cpu": round(info.get('cpu_percent') or 0, 2),
                "memory": round(info.get('memory_percent') or 0, 2),
                "cmdline": " ".join(cmdline) if cmdline else ""
            }
            result["processes"].append(entry)

            # Suspicious detection
            if _is_suspicious(entry):
                result["suspicious"].append(entry)

            # High usage
            if entry["cpu"] > 50:
                result["high_cpu"].append(entry)
            if entry["memory"] > 20:
                result["high_memory"].append(entry)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as e:
            logger.debug(f"Error reading process: {e}")
            continue

    result["summary"] = {
        "total": len(result["processes"]),
        "suspicious": len(result["suspicious"]),
        "high_cpu": len(result["high_cpu"]),
        "high_memory": len(result["high_memory"])
    }

    if not result["processes"] and _is_android():
        result["warning"] = (
            "No readable processes found. "
            "You may need to run outside Android restrictions."
        )

    return result


def _is_suspicious(entry):
    """Detect suspicious processes based on simple heuristics."""
    suspicious_names = {
        'nc', 'netcat', 'ncat', 'socat',
        'nmap', 'masscan', 'hydra',
        'msfconsole', 'meterpreter',
        'miner', 'xmrig', 'cpuminer'
    }
    name = (entry.get("name") or "").lower()
    cmdline = (entry.get("cmdline") or "").lower()

    for s in suspicious_names:
        if s in name or s in cmdline:
            return True

    # Processes from temporary paths
    for path in ('/tmp/', '/dev/shm/', '/data/local/tmp/'):
        if path in cmdline:
            return True

    return False


def print_process_report(result):
    """Print the process report in a readable format."""
    print("\n" + "=" * 70)
    print("  Process Analysis Report - SentinelX")
    print("=" * 70)

    if result.get("error"):
        print(f"\n[!] Error: {result['error']}")
        if result.get("warning"):
            print(f"[!] {result['warning']}")
        return

    s = result.get("summary", {})
    print(f"\n[*] Total processes: {s.get('total', 0)}")
    print(f"[*] Suspicious: {s.get('suspicious', 0)}")
    print(f"[*] High CPU: {s.get('high_cpu', 0)}")
    print(f"[*] High memory: {s.get('high_memory', 0)}")

    if result.get("warning"):
        print(f"\n[!] {result['warning']}")

    if result.get("suspicious"):
        print("\n[!] Suspicious processes:")
        for p in result["suspicious"][:10]:
            print(f"    ⚠ PID {p['pid']}: {p['name']} ({p['user']})")
            if p['cmdline']:
                print(f"       CMD: {p['cmdline'][:80]}")

    if result.get("high_cpu"):
        print("\n[*] High CPU usage:")
        for p in sorted(result["high_cpu"], key=lambda x: x['cpu'], reverse=True)[:5]:
            print(f"    • {p['name']} (PID {p['pid']}): {p['cpu']}%")

    if result.get("processes"):
        print(f"\n[*] First 10 processes:")
        for p in result["processes"][:10]:
            print(f"    • [{p['pid']:>6}] {p['name']:<20} {p['status']:<10} "
                  f"CPU:{p['cpu']:>5}% MEM:{p['memory']:>5}%")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    r = run_process_triage()
    print_process_report(r)
