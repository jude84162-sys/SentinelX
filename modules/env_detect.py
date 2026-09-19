# modules/env_detect.py
"""
SentinelX - Environment Detection
Detects Android/Termux, WSL, Kali, Linux, macOS and probes capabilities.
"""

import os
import platform
import shutil
import subprocess


def get_environment():
    system = platform.system().lower()
    release = platform.release().lower()

    env = {
        "os": system,
        "release": platform.release(),
        "platform": platform.platform(),
        "machine": platform.machine().lower(),
        "is_android": False,
        "is_termux": False,
        "is_wsl": False,
        "is_kali": False,
        "is_linux": False,
        "is_macos": False,
        "is_root": False,
        "has_proc_net": False,
        "has_proc_pids": False,
        "has_pm_command": False,
        "has_termux_api": False,
        "has_desktop_notify": False,
        "has_phonenumbers": False,
        "has_pkg_manager": None,
        "capabilities": {}
    }

    # --- Android / Termux ---
    if "android" in platform.platform().lower():
        env["is_android"] = True
    if os.environ.get("TERMUX_VERSION") or "com.termux" in os.environ.get("PREFIX", ""):
        env["is_termux"] = True
        env["is_android"] = True

    # --- WSL ---
    if "microsoft" in release or "microsoft" in platform.version().lower():
        env["is_wsl"] = True
    if os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
        env["is_wsl"] = True
    if os.environ.get("WSL_DISTRO_NAME"):
        env["is_wsl"] = True

    # --- Kali ---
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                content = f.read().lower()
                if "kali" in content:
                    env["is_kali"] = True
    except Exception:
        pass

    env["is_linux"] = system == "linux"
    env["is_macos"] = system == "darwin"

    # --- Root ---
    try:
        env["is_root"] = os.geteuid() == 0
    except AttributeError:
        env["is_root"] = False

    # --- /proc/net/tcp readable? ---
    try:
        with open("/proc/net/tcp") as f:
            f.read(1)
        env["has_proc_net"] = True
    except (PermissionError, FileNotFoundError, IsADirectoryError):
        env["has_proc_net"] = False

    # --- /proc/[pid] readable? ---
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
        env["has_proc_pids"] = len(pids) > 0
    except Exception:
        env["has_proc_pids"] = False

    # --- pm command ---
    try:
        r = subprocess.run(["which", "pm"], capture_output=True, timeout=2)
        env["has_pm_command"] = r.returncode == 0
    except Exception:
        pass

    # --- Termux:API availability ---
    if env["is_termux"]:
        try:
            r = subprocess.run(
                ["timeout", "8", "termux-battery-status"],
                capture_output=True, text=True, timeout=12
            )
            env["has_termux_api"] = r.returncode == 0 and bool(r.stdout.strip())
        except Exception:
            env["has_termux_api"] = False

    # --- Desktop notification tools ---
    if env["is_macos"]:
        env["has_desktop_notify"] = shutil.which("osascript") is not None
    elif env["is_linux"] and not env["is_termux"]:
        env["has_desktop_notify"] = (
            shutil.which("notify-send") is not None or
            shutil.which("zenity") is not None or
            shutil.which("powershell.exe") is not None  # WSL→Windows
        )

    # --- phonenumbers library ---
    try:
        import phonenumbers  # noqa
        env["has_phonenumbers"] = True
    except ImportError:
        env["has_phonenumbers"] = False

    # --- Package manager ---
    for pm in ["apt", "apk", "dnf", "yum", "pacman", "brew"]:
        try:
            r = subprocess.run(["which", pm], capture_output=True, timeout=2)
            if r.returncode == 0:
                env["has_pkg_manager"] = pm
                break
        except Exception:
            continue

    # --- Capabilities summary ---
    env["capabilities"] = {
        "process_triage": env["has_proc_pids"],
        "network_triage": env["has_proc_net"],
        "file_triage": True,
        "persistence_check": True,
        "android_osint": env["is_android"],
        "android_network": env["has_termux_api"],
        "android_spyware": env["has_termux_api"],
        "notifications": env["has_termux_api"] or env["has_desktop_notify"],
        "phone_osint": env["has_phonenumbers"],
        "system_logs": os.path.exists("/var/log") and os.access("/var/log", os.R_OK),
        "suid_scan": env["is_linux"],
        "package_audit": env["has_pkg_manager"] is not None,
    }

    return env


def get_env_label(env):
    if env["is_termux"]:
        return "Termux (Android)"
    if env["is_wsl"]:
        distro = os.environ.get("WSL_DISTRO_NAME", "WSL")
        return f"WSL ({distro})"
    if env["is_kali"]:
        return "Kali Linux"
    if env["is_linux"]:
        return "Linux"
    if env["is_macos"]:
        return "macOS"
    return platform.system()


def print_env_info(env):
    label = get_env_label(env)
    print(f"\n[*] Environment:   {label}")
    print(f"[*] Platform:      {env['platform']}")
    print(f"[*] Root:          {'YES ✓' if env['is_root'] else 'no'}")
    print(f"[*] Termux:API:    {'✓' if env['has_termux_api'] else '✗'}")
    print(f"[*] Desktop notif: {'✓' if env['has_desktop_notify'] else '✗'}")
    print(f"[*] phonenumbers:  {'✓' if env['has_phonenumbers'] else '✗'}")

    caps = env["capabilities"]
    available = [k for k, v in caps.items() if v]
    unavailable = [k for k, v in caps.items() if not v]

    if available:
        print(f"[✓] Available:     {', '.join(available)}")
    if unavailable:
        print(f"[✗] Unavailable:   {', '.join(unavailable)}")


if __name__ == "__main__":
    env = get_environment()
    print_env_info(env)
    import json
    print(json.dumps(env, indent=2))
