# modules/network.py
"""
SentinelX - Network Analysis Module
Full support on Linux/WSL/Kali. Graceful fallback on Android/Termux.
"""

import psutil
import socket
import logging
from datetime import datetime

from modules.env_detect import get_environment, get_env_label

logger = logging.getLogger("SentinelX.network")


def _safe_net_connections(kind='inet'):
    try:
        return list(psutil.net_connections(kind=kind)), None
    except PermissionError:
        return None, "Permission denied: /proc/net/* blocked"
    except FileNotFoundError:
        return None, "/proc/net/* not found"
    except Exception as e:
        return None, f"Unexpected error: {e}"


def _get_netstat_fallback():
    """Try ss, then netstat."""
    import subprocess
    for cmd in (["ss", "-tunap"], ["netstat", "-tunap"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout:
                return r.stdout, cmd[0]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None, None


def _format_connection(conn):
    try:
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if getattr(conn, 'laddr', None) else "-"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if getattr(conn, 'raddr', None) else "-"
        status = getattr(conn, 'status', 'N/A')
        pid = getattr(conn, 'pid', None)

        pname = "N/A"
        if pid:
            try:
                pname = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = f"PID:{pid}"

        return {
            "local": laddr,
            "remote": raddr,
            "status": status,
            "pid": pid,
            "process": pname,
            "family": "IPv4" if getattr(conn, 'family', None) == socket.AF_INET else "IPv6",
            "type": "TCP" if getattr(conn, 'type', None) == socket.SOCK_STREAM else "UDP"
        }
    except Exception as e:
        logger.debug(f"Format error: {e}")
        return None


def _is_suspicious(conn):
    suspicious_ports = {4444, 5555, 31337, 12345, 6666, 6667}
    remote = conn.get("remote", "-")
    if remote != "-":
        try:
            port = int(remote.split(":")[-1])
            if port in suspicious_ports:
                return True
        except (ValueError, IndexError):
            pass
    return False


def run_network_analysis():
    env = get_environment()

    result = {
        "timestamp": datetime.now().isoformat(),
        "environment": get_env_label(env),
        "platform": env["platform"],
        "is_android": env["is_android"],
        "connections": [],
        "listening_ports": [],
        "established": [],
        "suspicious": [],
        "summary": {},
        "error": None,
        "source": None,
        "warning": None
    }

    conns, error = _safe_net_connections('inet')

    if conns is None:
        # Fallback to ss/netstat
        fallback, source = _get_netstat_fallback()
        if fallback is None:
            result["error"] = error or "Unable to read network connections"
            if env["is_android"]:
                result["warning"] = (
                    "Android blocks /proc/net/tcp. Full network analysis requires root. "
                    "This module works fully on WSL/Kali/Linux."
                )
            return result
        else:
            result["source"] = source
            result["raw_output"] = fallback
            result["warning"] = f"Used {source} as fallback (less detailed)"
            return result

    result["source"] = "psutil"

    for conn in conns:
        formatted = _format_connection(conn)
        if not formatted:
            continue
        result["connections"].append(formatted)

        if formatted["status"] == "LISTEN":
            result["listening_ports"].append(formatted)
        elif formatted["status"] == "ESTABLISHED":
            result["established"].append(formatted)

        if _is_suspicious(formatted):
            result["suspicious"].append(formatted)

    result["summary"] = {
        "total_connections": len(result["connections"]),
        "listening_ports": len(result["listening_ports"]),
        "established": len(result["established"]),
        "suspicious": len(result["suspicious"])
    }

    return result


def print_network_report(result):
    print("\n" + "=" * 70)
    print("  Network Analysis Report - SentinelX")
    print("=" * 70)

    print(f"\n[*] Environment: {result.get('environment', 'unknown')}")

    if result.get("error"):
        print(f"\n[!] Error: {result['error']}")
        if result.get("warning"):
            print(f"[!] Warning: {result['warning']}")
        if result.get("raw_output"):
            print("\n--- fallback output ---")
            print(result["raw_output"][:2000])
        return

    if result.get("warning"):
        print(f"\n[!] Warning: {result['warning']}")

    s = result.get("summary", {})
    print(f"\n[*] Source: {result.get('source', 'N/A')}")
    print(f"[*] Total connections: {s.get('total_connections', 0)}")
    print(f"[*] Listening ports: {s.get('listening_ports', 0)}")
    print(f"[*] Established: {s.get('established', 0)}")
    print(f"[*] Suspicious: {s.get('suspicious', 0)}")

    if result.get("suspicious"):
        print("\n[!] Suspicious connections:")
        for c in result["suspicious"]:
            print(f"    ⚠ {c['local']} -> {c['remote']} [{c['status']}] ({c['process']})")

    if result.get("listening_ports"):
        print("\n[*] Listening ports:")
        for c in result["listening_ports"][:20]:
            print(f"    • {c['local']} ({c['process']})")
        if len(result["listening_ports"]) > 20:
            print(f"    ... and {len(result['listening_ports']) - 20} more")

    if result.get("established"):
        print("\n[*] Established connections:")
        for c in result["established"][:20]:
            print(f"    → {c['local']} -> {c['remote']} ({c['process']})")
        if len(result["established"]) > 20:
            print(f"    ... and {len(result['established']) - 20} more")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    r = run_network_analysis()
    print_network_report(r)
