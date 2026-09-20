# modules/daemon.py
"""
SentinelX - Background Daemon (Battery-Efficient)
Runs triage periodically, alerts only on changes.
Adapts to battery state. Uses light scan to detect when full scan is needed.
"""

import os
import json
import time
import signal
import logging
import platform
import subprocess
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("SentinelX.daemon")

BASE_DIR = Path(__file__).parent.parent
STATE_DIR = BASE_DIR / "state"
STATE_DIR.mkdir(exist_ok=True)

BASELINE_FILE = STATE_DIR / "baseline.json"
LIGHT_CACHE = STATE_DIR / "light_cache.json"
ALERTS_LOG = STATE_DIR / "alerts.log"
DAEMON_PID = STATE_DIR / "daemon.pid"
DAEMON_OUT = STATE_DIR / "daemon.out"


# ============================================================
# Helpers
# ============================================================

def _is_android():
    return "android" in platform.platform().lower()


def _run_cmd(cmd, timeout=10):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def _load_json(path, default=None):
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return default


def _save_json(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception as e:
        logger.debug(f"Save failed: {e}")


def _log_alert(message):
    try:
        with open(ALERTS_LOG, "a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] {message}\n")
    except Exception:
        pass


# ============================================================
# Battery management
# ============================================================

def get_battery_state():
    """Return (percentage, is_charging) or (None, None)."""
    if _is_android():
        out = _run_cmd(["termux-battery-status"], timeout=10)
        if out:
            try:
                data = json.loads(out)
                pct = data.get("percentage")
                status = data.get("status", "")
                plugged = data.get("plugged", "UNPLUGGED")
                charging = status == "CHARGING" or plugged != "UNPLUGGED"
                return pct, charging
            except Exception:
                pass
    return None, None


def get_scan_interval():
    """
    Battery-adaptive scan interval (seconds).
    Returns None if monitoring should pause.
    """
    pct, charging = get_battery_state()

    # No battery info → desktop
    if pct is None:
        return 1800  # 30 min

    if charging:
        return 900  # 15 min (battery free)

    if pct >= 50:
        return 1800  # 30 min
    elif pct >= 20:
        return 3600  # 60 min
    else:
        return None  # pause (<20%)


# ============================================================
# Notifications
# ============================================================

def _notify(title, message, priority="default"):
    pct, charging = get_battery_state()
    use_sound = priority == "high" and (charging or pct is None or pct > 30)

    if _is_android():
        try:
            cmd = ["termux-notification",
                   "--title", title,
                   "--content", message,
                   "--priority", priority,
                   "--id", "sentinelx-daemon"]
            if use_sound:
                cmd.append("--sound")
                cmd.extend(["--vibrate", "500,200,500"])
            subprocess.run(cmd, timeout=10, capture_output=True)
            return True
        except Exception:
            pass

    # Desktop
    try:
        urgency = "critical" if use_sound else "normal"
        subprocess.run(
            ["notify-send", "-u", urgency, "-a", "SentinelX", title, message],
            timeout=5, capture_output=True
        )
        return True
    except Exception:
        pass

    logger.info(f"[NOTIFY] {title}: {message}")
    return False


# ============================================================
# Scans
# ============================================================

def _light_fingerprint():
    """Fast fingerprint (~1s). Returns dict."""
    fp = {}

    # Process count
    try:
        import psutil
        fp["process_count"] = len(psutil.pids())
    except Exception:
        fp["process_count"] = 0

    # Package count (Android, fast via cmd)
    if _is_android():
        out = _run_cmd(["cmd", "package", "list", "packages", "-3"], timeout=10)
        if out:
            fp["package_count"] = sum(
                1 for l in out.splitlines() if l.startswith("package:")
            )

    # Public IP
    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            fp["public_ip"] = r.read().decode().strip()
    except Exception:
        pass

    # Battery
    pct, charging = get_battery_state()
    fp["battery"] = f"{pct}|{charging}"

    return fp


def _light_scan():
    """Returns True if a full scan is needed."""
    fp = _light_fingerprint()
    old = _load_json(LIGHT_CACHE)

    if old is None:
        _save_json(LIGHT_CACHE, fp)
        return True

    # Compare key fields (ignore battery)
    changed = False
    for key in ("process_count", "package_count", "public_ip"):
        if old.get(key) != fp.get(key):
            logger.info(f"Light scan: {key} changed "
                        f"({old.get(key)} → {fp.get(key)})")
            changed = True

    _save_json(LIGHT_CACHE, fp)
    return changed


def _run_full_scan():
    """Run full triage, compare with baseline, alert on changes."""
    from modules.process import run_process_triage
    from modules.resources import run_resource_check
    from modules.android_osint import run_android_osint
    from modules.android_spyware import run_android_spyware_check

    logger.info("Running full scan...")

    current = {
        "timestamp": datetime.now().isoformat(),
        "processes": run_process_triage(),
        "resources": run_resource_check(),
        "android_osint": run_android_osint(),
        "android_spyware": run_android_spyware_check(),
    }

    baseline = _load_json(BASELINE_FILE)

    if baseline is None:
        _save_json(BASELINE_FILE, current)
        _notify("SentinelX Active",
                "Background monitoring started. Baseline created.",
                priority="low")
        return []

    changes = _detect_changes(baseline, current)

    if changes:
        for c in changes:
            _log_alert(c)

        important = [c for c in changes if "[ALERT]" in c or "Suspicious" in c]
        if important:
            _notify(f"SentinelX ALERT ({len(important)})",
                    "\n".join(important[:3]),
                    priority="high")
        else:
            _notify(f"SentinelX ({len(changes)} changes)",
                    "\n".join(changes[:3]),
                    priority="default")

    _save_json(BASELINE_FILE, current)
    return changes


def _detect_changes(old, new):
    """Compare reports, return list of change descriptions."""
    changes = []

    # Processes
    old_procs = {p.get("name", "") for p in
                 (old.get("processes", {}).get("processes") or [])}
    new_procs = {p.get("name", "") for p in
                 (new.get("processes", {}).get("processes") or [])}
    for n in (new_procs - old_procs):
        changes.append(f"New process: {n}")

    # Packages
    old_pkgs = {p.get("package", "") for p in
                (old.get("android_osint", {}).get("packages") or [])}
    new_pkgs = {p.get("package", "") for p in
                (new.get("android_osint", {}).get("packages") or [])}
    for p in (new_pkgs - old_pkgs):
        changes.append(f"New app: {p}")

    # Suspicious apps
    old_sus = {p.get("package", "") for p in
               (old.get("android_osint", {}).get("suspicious") or [])}
    new_sus = {p.get("package", "") for p in
               (new.get("android_osint", {}).get("suspicious") or [])}
    for p in (new_sus - old_sus):
        changes.append(f"[ALERT] Suspicious app detected: {p}")

    # Spyware alerts
    old_alerts = old.get("android_spyware", {}).get("summary", {}).get("alerts", 0)
    new_alerts = new.get("android_spyware", {}).get("summary", {}).get("alerts", 0)
    if new_alerts > old_alerts:
        changes.append(f"[ALERT] {new_alerts - old_alerts} new spyware indicator(s)")

    # Resource warnings
    old_w = old.get("resources", {}).get("summary", {}).get("warnings", 0)
    new_w = new.get("resources", {}).get("summary", {}).get("warnings", 0)
    if new_w > old_w:
        changes.append(f"[ALERT] {new_w - old_w} new resource warning(s)")

    return changes


# ============================================================
# Daemon loop
# ============================================================

_running = True


def _signal_handler(signum, frame):
    global _running
    logger.info(f"Signal {signum} — shutting down")
    _running = False


def _acquire_wake_lock():
    if _is_android():
        try:
            subprocess.run(["termux-wake-lock"], timeout=5, capture_output=True)
        except Exception:
            pass


def _release_wake_lock():
    if _is_android():
        try:
            subprocess.run(["termux-wake-unlock"], timeout=5, capture_output=True)
        except Exception:
            pass


def start_daemon(once=False):
    """Main daemon loop."""
    global _running

    # Prevent duplicate daemons
    if DAEMON_PID.exists() and not once:
        try:
            with open(DAEMON_PID) as f:
                old_pid = int(f.read().strip())
            os.kill(old_pid, 0)
            logger.error(f"Daemon already running (PID {old_pid})")
            print(f"[!] Already running (PID {old_pid})")
            return
        except (OSError, ValueError):
            DAEMON_PID.unlink(missing_ok=True)

    with open(DAEMON_PID, "w") as f:
        f.write(str(os.getpid()))

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    logger.info(f"Daemon started (PID {os.getpid()})")

    cycle = 0
    try:
        while _running:
            cycle += 1

            interval = get_scan_interval()
            if interval is None:
                logger.info("Battery low — pausing")
                for _ in range(600):
                    if not _running:
                        break
                    time.sleep(1)
                    pct, charging = get_battery_state()
                    if charging or (pct and pct > 25):
                        break
                continue

            # Sleep before next cycle (except first)
            if not once and cycle > 1:
                logger.debug(f"Sleeping {interval}s...")
                for _ in range(interval):
                    if not _running:
                        break
                    time.sleep(1)

            if not _running:
                break

            # Light scan
            try:
                needs_full = _light_scan()
            except Exception as e:
                logger.error(f"Light scan failed: {e}")
                needs_full = True

            # Full scan only if needed
            if needs_full:
                _acquire_wake_lock()
                try:
                    _run_full_scan()
                except Exception as e:
                    logger.error(f"Full scan failed: {e}")
                finally:
                    _release_wake_lock()

            if once:
                break

    finally:
        DAEMON_PID.unlink(missing_ok=True)
        _release_wake_lock()
        logger.info("Daemon stopped")


def stop_daemon():
    if not DAEMON_PID.exists():
        print("[!] Not running")
        return False
    try:
        with open(DAEMON_PID) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        print(f"[+] Stop signal sent to PID {pid}")
        return True
    except Exception as e:
        print(f"[!] Failed: {e}")
        return False


def daemon_status():
    if not DAEMON_PID.exists():
        print("[i] Daemon: NOT running")
        return False
    try:
        with open(DAEMON_PID) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)

        pct, charging = get_battery_state()
        print(f"[+] Daemon: RUNNING (PID {pid})")

        if pct is not None:
            print(f"[+] Battery: {pct}% ({'charging' if charging else 'on battery'})")
            if charging:
                print(f"[+] Next scan: ~15 min (charging)")
            elif pct >= 50:
                print(f"[+] Next scan: ~30 min")
            elif pct >= 20:
                print(f"[+] Next scan: ~60 min (low battery)")
            else:
                print(f"[+] Next scan: PAUSED (<20%)")

        if ALERTS_LOG.exists():
            lines = ALERTS_LOG.read_text().splitlines()[-10:]
            if lines:
                print(f"\nRecent alerts:")
                for line in lines:
                    print(f"  {line}")
        return True
    except (OSError, ValueError):
        print("[!] Stale PID — cleaning up")
        DAEMON_PID.unlink(missing_ok=True)
        return False


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(message)s')
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "status":
            daemon_status()
        elif cmd == "stop":
            stop_daemon()
        elif cmd == "once":
            _run_full_scan()
            print("[+] Single scan done")
        else:
            print(f"Unknown: {cmd}")
    else:
        start_daemon()
