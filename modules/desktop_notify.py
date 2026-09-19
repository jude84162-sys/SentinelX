# modules/desktop_notify.py
"""
SentinelX - Desktop Notifications
Cross-platform: Linux (notify-send), macOS (osascript), Windows (win10toast),
WSL (falls back to Windows via powershell.exe).
"""

import subprocess
import shutil
import platform
import logging

logger = logging.getLogger("SentinelX.desktop_notify")


def _is_wsl():
    return "microsoft" in platform.release().lower() or \
           "microsoft" in platform.version().lower()


def _has(cmd):
    return shutil.which(cmd) is not None


def _run(cmd, timeout=10):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    except Exception as e:
        logger.debug(f"Notify error: {e}")
        return False


def notify(title, content, urgency="normal"):
    """
    Send a desktop notification.
    urgency: low, normal, critical
    """
    system = platform.system().lower()

    # Linux native
    if system == "linux" and not _is_wsl():
        if _has("notify-send"):
            return _run([
                "notify-send",
                "-u", urgency,
                "-a", "SentinelX",
                title, content
            ])
        # Fallback to zenity
        if _has("zenity"):
            return _run([
                "zenity", "--info",
                "--title", f"SentinelX: {title}",
                "--text", content,
                "--timeout", "10"
            ])

    # WSL — use Windows toast via PowerShell
    if _is_wsl():
        if _has("powershell.exe"):
            ps = (
                "[reflection.assembly]::loadwithpartialname('System.Windows.Forms');"
                "[reflection.assembly]::loadwithpartialname('System.Drawing');"
                "$notify = New-Object System.Windows.Forms.NotifyIcon;"
                "$notify.Icon = [System.Drawing.SystemIcons]::Information;"
                "$notify.Visible = $true;"
                f"$notify.ShowBalloonTip(10000, 'SentinelX: {title}', '{content}', "
                "[System.Windows.Forms.ToolTipIcon]::Info);"
            )
            return _run(["powershell.exe", "-NoProfile", "-Command", ps])

    # macOS
    if system == "darwin":
        if _has("osascript"):
            script = f'display notification "{content}" with title "SentinelX: {title}"'
            return _run(["osascript", "-e", script])

    # Fallback — log to console
    logger.info(f"[NOTIFY] {title}: {content}")
    print(f"\n[🔔] {title}: {content}\n")
    return True


def alert_critical(title, detail):
    """Critical alert with maximum urgency."""
    return notify(title, detail, urgency="critical")


def send_summary_notification(report):
    """Extract summary counts and send desktop notification."""
    suspicious = 0
    critical = 0

    def _walk(obj):
        nonlocal suspicious, critical
        if isinstance(obj, dict):
            if isinstance(obj.get("suspicious"), int):
                suspicious += obj["suspicious"]
            if isinstance(obj.get("suspicious_count"), int):
                suspicious += obj["suspicious_count"]
            if isinstance(obj.get("high_severity"), int):
                critical += obj["high_severity"]
            if isinstance(obj.get("critical_permission_apps"), int):
                critical += obj["critical_permission_apps"]
            if isinstance(obj.get("risk_level")):
                if obj["risk_level"] in ("HIGH", "CRITICAL"):
                    critical += 1
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict) and item.get("severity") == "HIGH":
                    critical += 1

    _walk(report)

    if suspicious == 0 and critical == 0:
        notify("✓ Triage Complete", "No suspicious findings", urgency="low")
    elif critical > 0:
        notify("🚨 SentinelX Alert",
               f"{critical} critical, {suspicious} total findings",
               urgency="critical")
    else:
        notify("⚠ SentinelX",
               f"{suspicious} findings to review",
               urgency="normal")


if __name__ == "__main__":
    print("Testing desktop notifications...")
    print(f"Linux notify-send: {_has('notify-send')}")
    print(f"WSL detection:     {_is_wsl()}")
    print(f"powershell.exe:    {_has('powershell.exe')}")
    notify("SentinelX Test", "Desktop notifications working", urgency="normal")
    print("Done. Check your desktop.")
