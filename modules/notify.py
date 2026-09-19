# modules/notify.py
"""
SentinelX - Native Android Notifications
Sends findings as toast/notification/vibration/voice alerts via Termux:API.
"""

import subprocess
import logging
import platform
import json

logger = logging.getLogger("SentinelX.notify")


def _is_android():
    return "android" in platform.platform().lower()


def _run(cmd, timeout=15):
    """Run a command safely. Longer default timeout for slow Termux:API calls."""
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


def toast(message, short=True):
    """Show a toast message on screen."""
    if not _is_android():
        return False
    cmd = ["termux-toast"]
    if short:
        cmd.append("-s")
    cmd.append(message)
    return _run(cmd, timeout=10)


def notify(title, content, priority="default", sound=True, vibrate=True):
    """Send a native Android notification."""
    if not _is_android():
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

    return _run(cmd, timeout=10)


def vibrate(pattern="500"):
    """Vibrate the device. Uses only the first duration value."""
    if not _is_android():
        return False
    duration = pattern.split(",")[0] if isinstance(pattern, str) else str(pattern)
    return _run(["termux-vibrate", "-d", duration], timeout=10)


def speak(text, wait=False):
    """
    Text-to-speech.
    wait=False: non-blocking (default, returns immediately)
    wait=True:  blocking (waits for speech to finish)
    """
    if not _is_android():
        return False
    cmd = ["termux-tts-speak"]
    if not wait:
        cmd.append("-n")  # non-blocking flag
    cmd.append(text)
    return _run(cmd, timeout=20)


def dialog_confirm(title, message):
    """Show a native confirmation dialog. Returns True if user pressed Yes."""
    if not _is_android():
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
    if not _is_android():
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
    notify(f"⚠️ SentinelX: {finding_type}", detail, priority="high")
    vibrate("1000")
    toast(f"⚠️ {finding_type}")


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
        notify("✓ SentinelX", "Triage complete — no suspicious findings",
               priority="low", sound=False, vibrate=False)
    elif critical_count > 0:
        notify("🚨 SentinelX Alert",
               f"Triage complete — {critical_count} critical, {suspicious_count} total",
               priority="high")
        vibrate("1000")
    else:
        notify("⚠ SentinelX",
               f"Triage complete — {suspicious_count} findings to review",
               priority="default")


if __name__ == "__main__":
    import logging as _lg
    _lg.basicConfig(level=logging.DEBUG)
    print("Testing notifications...")

    print("1. Toast...")
    print(f"   {'✓' if toast('SentinelX test') else '✗'}")

    print("2. Notification...")
    print(f"   {'✓' if notify('SentinelX Test', 'Notification works', priority='high') else '✗'}")

    print("3. Vibrate...")
    print(f"   {'✓' if vibrate('500') else '✗'}")

    print("4. Speak (non-blocking)...")
    print(f"   {'✓' if speak('Sentinel X test') else '✗'}")

    print("Done. Check your device.")
