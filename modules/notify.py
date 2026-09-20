# modules/notify.py
"""
SentinelX - Native Android Notifications (Termux:API)
Sends findings as toast/notification/vibration alerts via Termux:API.
TTS is non-blocking by default to avoid hangs on Android 14+.
"""

import subprocess
import logging
import platform
import json
import shutil

logger = logging.getLogger("SentinelX.notify")


def _is_android():
    return "android" in platform.platform().lower()


def _has_cmd(name):
    """Check if a command is available."""
    return shutil.which(name) is not None


def _run(cmd, timeout=10):
    """Run a command safely. Returns True on success."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0 and result.stderr:
            logger.debug(f"Command failed: {' '.join(cmd)}: {result.stderr.strip()}")
        return result.returncode == 0
    except FileNotFoundError:
        logger.debug(f"Command not found: {cmd[0]}")
        return False
    except subprocess.TimeoutExpired:
        logger.debug(f"Timeout: {' '.join(cmd)}")
        return False
    except Exception as e:
        logger.debug(f"Error: {e}")
        return False


def _run_detached(cmd):
    """Run command without waiting (fire-and-forget)."""
    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except FileNotFoundError:
        logger.debug(f"Command not found: {cmd[0]}")
        return False
    except Exception as e:
        logger.debug(f"Detached run failed: {e}")
        return False


# --- Public API ---

def toast(message, short=True):
    """Show a toast message on screen."""
    if not _is_android() or not _has_cmd("termux-toast"):
        return False
    cmd = ["termux-toast"]
    if short:
        cmd.append("-s")
    cmd.append(message)
    return _run(cmd, timeout=5)


def notify(title, content, priority="default", sound=True, vibrate=True):
    """Send a native Android notification."""
    if not _is_android() or not _has_cmd("termux-notification"):
        return False

    cmd = [
        "termux-notification",
        "--title", title,
        "--content", content,
        "--priority", priority,
        "--id", "sentinelx"
    ]

    if sound:
        cmd.append("--sound")

    if vibrate:
        cmd.append("--vibrate")
        cmd.append("500,200,500")

    return _run(cmd, timeout=8)


def vibrate(pattern="500"):
    """Vibrate the device. Uses only the first duration value."""
    if not _is_android() or not _has_cmd("termux-vibrate"):
        return False
    duration = pattern.split(",")[0] if isinstance(pattern, str) else str(pattern)
    return _run(["termux-vibrate", "-d", duration], timeout=5)


def speak(text, wait=False):
    """
    Text-to-speech. Non-blocking by default to avoid hangs.
    wait=False: fire-and-forget (recommended)
    wait=True:  blocking (waits up to 15s)
    """
    if not _is_android() or not _has_cmd("termux-tts-speak"):
        return False

    cmd = ["termux-tts-speak"]

    if not wait:
        # Fire-and-forget: don't wait for TTS to finish
        return _run_detached(cmd + [text])
    else:
        # Blocking mode with longer timeout
        return _run(cmd + [text], timeout=15)


def dialog_confirm(title, message):
    """Show a native confirmation dialog. Returns True if user pressed Yes."""
    if not _is_android() or not _has_cmd("termux-dialog"):
        return False
    try:
        result = subprocess.run(
            ["termux-dialog", "confirm", "-t", title, "-i", message],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return False
        data = json.loads(result.stdout)
        return data.get("text") == "yes"
    except Exception:
        return False


def dialog_text(title, hint=""):
    """Show a text input dialog."""
    if not _is_android() or not _has_cmd("termux-dialog"):
        return None
    try:
        result = subprocess.run(
            ["termux-dialog", "text", "-t", title, "-i", hint],
            capture_output=True, text=True, timeout=90
        )
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout)
        return data.get("text")
    except Exception:
        return None


def alert_critical(finding_type, detail):
    """Send a HIGH severity alert through multiple channels."""
    if not _is_android():
        return
    notify(f"SentinelX: {finding_type}", detail, priority="high")
    vibrate("1000")
    toast(f"[!] {finding_type}")


def send_summary_notification(report):
    """Send a summary notification after triage."""
    if not _is_android():
        return

    suspicious_count = 0
    critical_count = 0

    def _walk(obj):
        nonlocal suspicious_count, critical_count
        if isinstance(obj, dict):
            if isinstance(obj.get("suspicious"), int):
                suspicious_count += obj["suspicious"]
            if isinstance(obj.get("suspicious_count"), int):
                suspicious_count += obj["suspicious_count"]
            if isinstance(obj.get("high_severity"), int):
                critical_count += obj["high_severity"]
            if isinstance(obj.get("critical_permission_apps"), int):
                critical_count += obj["critical_permission_apps"]
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict) and item.get("severity") == "HIGH":
                    critical_count += 1

    _walk(report)

    if suspicious_count == 0 and critical_count == 0:
        notify("SentinelX OK", "Triage complete, no suspicious findings",
               priority="low", sound=False, vibrate=False)
    elif critical_count > 0:
        notify("SentinelX ALERT",
               f"Triage complete: {critical_count} critical, {suspicious_count} total",
               priority="high")
        vibrate("1000")
    else:
        notify("SentinelX",
               f"Triage complete: {suspicious_count} findings to review",
               priority="default")


# --- Self-test ---

if __name__ == "__main__":
    import logging as _lg
    _lg.basicConfig(level=logging.INFO)
    print("Testing notifications...")

    # Check availability
    print(f"Termux:API available: {_is_android()}")
    for cmd in ["termux-toast", "termux-notification", "termux-vibrate", "termux-tts-speak"]:
        print(f"  {cmd:<25} {'✓' if _has_cmd(cmd) else '✗'}")

    print()
    print("1. Toast...")
    print(f"   {'OK' if toast('SentinelX test') else 'FAIL'}")

    print("2. Notification...")
    print(f"   {'OK' if notify('SentinelX Test', 'Notification works', priority='high') else 'FAIL'}")

    print("3. Vibrate...")
    print(f"   {'OK' if vibrate('500') else 'FAIL'}")

    print("4. Speak (non-blocking)...")
    print(f"   {'OK (fire-and-forget)' if speak('Sentinel X test') else 'FAIL'}")

    print()
    print("Done. Check your device.")
