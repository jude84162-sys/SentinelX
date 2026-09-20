# modules/desktop_notify.py
"""
SentinelX - Desktop Notifications (Universal)
Supports: Linux (notify-send), macOS (osascript),
Windows (PowerShell toast), WSL (Windows bridge).
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


def _powershell_toast(title, content):
    """Send Windows toast via PowerShell."""
    ps = (
        "[reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null;"
        "[reflection.assembly]::loadwithpartialname('System.Drawing') | Out-Null;"
        "$n = New-Object System.Windows.Forms.NotifyIcon;"
        "$n.Icon = [System.Drawing.SystemIcons]::Information;"
        "$n.Visible = $true;"
        f"$n.ShowBalloonTip(10000, '{title}', '{content}', "
        "[System.Windows.Forms.ToolTipIcon]::Info);"
    )
    # Native Windows
    if platform.system().lower() == "windows":
        for exe in ("powershell", "pwsh"):
            if _has(exe):
                return _run([exe, "-NoProfile", "-Command", ps], timeout=15)
    # WSL → Windows
    if _is_wsl() and _has("powershell.exe"):
        return _run(["powershell.exe", "-NoProfile", "-Command", ps], timeout=15)
    return False


def notify(title, content, urgency="normal"):
    """Send desktop notification on any platform."""
    system = platform.system().lower()

    # Windows
    if system == "windows":
        if _powershell_toast(title, content):
            return True

    # macOS
    if system == "darwin":
        if _has("osascript"):
            script = f'display notification "{content}" with title "SentinelX: {title}"'
            return _run(["osascript", "-e", script], timeout=10)

    # Linux native
    if system == "linux" and not _is_wsl():
        if _has("notify-send"):
            return _run([
                "notify-send", "-u", urgency, "-a", "SentinelX",
                title, content
            ])
        if _has("zenity"):
            return _run([
                "zenity", "--info",
                "--title", f"SentinelX: {title}",
                "--text", content,
                "--timeout", "10"
            ])

    # WSL → Windows
    if _is_wsl():
        if _powershell_toast(title, content):
            return True

    # Fallback: log
    logger.info(f"[NOTIFY] {title}: {content}")
    print(f"\n[🔔] {title}: {content}\n")
    return True


def alert_critical(title, detail):
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
            if isinstance(obj.get("risk_level"), str):
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
        notify("SentinelX OK", "Triage complete - no suspicious findings",
               urgency="low")
    elif critical > 0:
        notify("SentinelX ALERT",
               f"{critical} critical, {suspicious} total findings",
               urgency="critical")
    else:
        notify("SentinelX",
               f"{suspicious} findings to review",
               urgency="normal")


if __name__ == "__main__":
    print("Testing desktop notifications...")
    print(f"OS:             {platform.system()}")
    print(f"WSL:            {_is_wsl()}")
    print(f"notify-send:    {_has('notify-send')}")
    print(f"osascript:      {_has('osascript')}")
    print(f"powershell:     {_has('powershell')}")
    print(f"powershell.exe: {_has('powershell.exe')}")
    notify("SentinelX Test", "Desktop notifications working")
    print("Done.")
