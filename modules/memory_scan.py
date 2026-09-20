# modules/memory_scan.py
"""
SentinelX - Memory Scanner (Linux only)
Scans running processes' memory for malware patterns.

Note: Full memory scan requires root access.
Without root, only own processes can be scanned.
"""

import os
import re
import platform
import logging

logger = logging.getLogger("SentinelX.memory")


# ============================================================
# Patterns to search in process memory
# ============================================================

MEMORY_PATTERNS = [
    # Reverse shells
    (rb"nc -e /bin/(bash|sh)", "high", "Netcat reverse shell"),
    (rb"bash -i >& /dev/tcp/", "high", "Bash reverse shell"),
    (rb"bash -i >&/dev/tcp/", "high", "Bash reverse shell"),
    (rb"/bin/sh -i", "high", "SH reverse shell"),
    (rb"python -c 'import socket", "high", "Python reverse shell"),
    (rb"perl -e 'use Socket", "high", "Perl reverse shell"),

    # Web shells
    (rb"eval\(base64_decode", "high", "PHP webshell (base64)"),
    (rb"eval\(gzinflate", "high", "PHP webshell (gzinflate)"),
    (rb"system\(\$_GET", "high", "PHP system shell"),
    (rb"passthru\(\$_POST", "high", "PHP passthru shell"),
    (rb"shell_exec\(\$_POST", "high", "PHP shell_exec shell"),

    # Meterpreter / C2
    (rb"meterpreter", "critical", "Meterpreter payload"),
    (rb"metsrv", "critical", "Meterpreter server DLL"),
    (rb"stdapi", "critical", "Meterpreter stdapi"),

    # Ransomware
    (rb"Your files have been encrypted", "critical", "Ransomware note"),
    (rb"Send Bitcoin to", "critical", "Ransom demand"),

    # Miners
    (rb"stratum\+tcp://", "medium", "Crypto miner stratum"),

    # Generic suspicious
    (rb"/dev/tcp/", "medium", "Reverse shell redirection"),
    (rb"ncat -e", "high", "Ncat reverse shell"),
    (rb"socat.*EXEC", "high", "Socat reverse shell"),
]


# ============================================================
# Memory scanning
# ============================================================

def _is_linux():
    return platform.system().lower() == "linux"


def scan_process_memory(pid, max_bytes_per_region=1024 * 1024):
    """
    Scan a single process's memory for patterns.
    Returns list of matches.
    """
    if not _is_linux():
        return []

    maps_file = f"/proc/{pid}/maps"
    mem_file = f"/proc/{pid}/mem"

    if not os.path.exists(maps_file):
        return []

    matches = []
    checked_regions = 0

    try:
        with open(maps_file, "r") as f:
            maps = f.readlines()

        with open(mem_file, "rb") as mem:
            for line in maps:
                # Limit regions to scan (performance)
                if checked_regions > 200:
                    break

                m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S+)", line)
                if not m:
                    continue

                start = int(m.group(1), 16)
                end = int(m.group(2), 16)
                perms = m.group(3)

                # Only readable regions
                if "r" not in perms:
                    continue

                # Size limit
                size = end - start
                if size > max_bytes_per_region:
                    size = max_bytes_per_region

                try:
                    mem.seek(start)
                    data = mem.read(size)
                    checked_regions += 1
                except (OSError, ValueError):
                    continue

                # Search patterns
                for pattern, severity, description in MEMORY_PATTERNS:
                    if re.search(pattern, data, re.IGNORECASE):
                        matches.append({
                            "pid": pid,
                            "severity": severity,
                            "description": description,
                            "address": hex(start),
                            "region_size": size,
                        })
                        # One match per region per pattern is enough
                        break

    except (PermissionError, FileNotFoundError):
        # Normal without root or for other users' processes
        pass
    except Exception as e:
        logger.debug(f"Memory scan failed for PID {pid}: {e}")

    return matches


def scan_all_processes():
    """Scan all accessible processes."""
    if not _is_linux():
        return {
            "error": "Memory scanning only supported on Linux",
            "matches": [],
        }

    try:
        import psutil
    except ImportError:
        return {
            "error": "psutil not installed",
            "matches": [],
        }

    results = []
    processes_scanned = 0

    for proc in psutil.process_iter(["pid", "name", "username"]):
        try:
            pid = proc.info["pid"]
            matches = scan_process_memory(pid)
            processes_scanned += 1

            for m in matches:
                m["process"] = proc.info.get("name", "?")
                m["user"] = proc.info.get("username", "?")
                results.append(m)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            logger.debug(f"Process scan failed: {e}")
            continue

    return {
        "processes_scanned": processes_scanned,
        "matches": results,
    }


# ============================================================
# Report
# ============================================================

def print_memory_report(result):
    print("\n" + "=" * 70)
    print("  Memory Scanner Report - SentinelX")
    print("=" * 70)

    if result.get("error"):
        print(f"\n[!] {result['error']}")
        return

    print(f"\n[*] Processes scanned: {result.get('processes_scanned', 0)}")
    print(f"[*] Matches: {len(result.get('matches', []))}")

    matches = result.get("matches", [])
    if matches:
        # Group by severity
        by_sev = {}
        for m in matches:
            sev = m.get("severity", "unknown")
            by_sev.setdefault(sev, []).append(m)

        for sev in ("critical", "high", "medium", "low"):
            if sev not in by_sev:
                continue
            marker = "🔴" if sev in ("critical", "high") else "🟡"
            print(f"\n[!] {marker} {sev.upper()} ({len(by_sev[sev])}):")

            for m in by_sev[sev][:10]:
                print(f"    {marker} PID {m['pid']} ({m.get('process', '?')})")
                print(f"       {m['description']}")
                print(f"       Address: {m.get('address', '?')}")
    else:
        print(f"\n[✓] No suspicious patterns in memory")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    if not _is_linux():
        print("[!] Memory scanning is Linux-only")
        print(f"    Current platform: {platform.system()}")
        print(f"\n[i] On Termux: The scan will only access Termux processes")
        print(f"    (that's normal — Android sandboxes each app)")

    result = scan_all_processes()
    print_memory_report(result)
