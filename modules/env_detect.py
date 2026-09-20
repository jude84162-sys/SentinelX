# modules/env_detect.py
"""
SentinelX - Environment Detection (Universal)
Detects: Android/Termux, Linux, macOS, Windows, WSL, Docker, Kali.
Determines available capabilities per environment.
"""

import os
import platform
import shutil
import subprocess


def get_environment():
    system = platform.system().lower()
    release = platform.release().lower()
    machine = platform.machine().lower()

    env = {
        "os": system,
        "release": platform.release(),
        "platform": platform.platform(),
        "machine": machine,
        "python": platform.python_version(),

        # Platform flags
        "is_android": False,
        "is_termux": False,
        "is_wsl": False,
        "is_kali": False,
        "is_linux": False,
        "is_macos": False,
        "is_windows": False,
        "is_docker": False,
        "is_container": False,

        # Privilege
        "is_root": False,
        "is_admin": False,

        # Capabilities
        "has_proc_net": False,
        "has_proc_pids": False,
        "has_pm_command": False,
        "has_termux_api": False,
        "has_desktop_notify": False,
        "has_phonenumbers": False,
        "has_pkg_manager": None,
        "has_powershell": False,
        "has_cmd": False,
        "shell_type": None,

        "capabilities": {},
    }

    # ============================================================
    # Platform detection
    # ============================================================

    # Android / Termux
    if "android" in platform.platform().lower():
        env["is_android"] = True
    if os.environ.get("TERMUX_VERSION") or "com.termux" in os.environ.get("PREFIX", ""):
        env["is_termux"] = True
        env["is_android"] = True

    # WSL
    if "microsoft" in release or "microsoft" in platform.version().lower():
        env["is_wsl"] = True
    if os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
        env["is_wsl"] = True
    if os.environ.get("WSL_DISTRO_NAME"):
        env["is_wsl"] = True

    # Docker / container
    if os.path.exists("/.dockerenv"):
        env["is_docker"] = True
    if os.path.exists("/run/.containerenv"):
        env["is_container"] = True
    try:
        with open("/proc/1/cgroup") as f:
            if "docker" in f.read():
                env["is_docker"] = True
    except Exception:
        pass

    # Kali
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                content = f.read().lower()
                if "kali" in content:
                    env["is_kali"] = True
    except Exception:
        pass

    # Linux / macOS / Windows
    env["is_linux"] = system == "linux"
    env["is_macos"] = system == "darwin"
    env["is_windows"] = system == "windows"

    # Shell type
    if env["is_windows"]:
        env["has_powershell"] = shutil.which("powershell") is not None or \
                                 shutil.which("pwsh") is not None
        env["has_cmd"] = shutil.which("cmd") is not None
        env["shell_type"] = "powershell" if env["has_powershell"] else "cmd"

    # ============================================================
    # Privileges
    # ============================================================
    try:
        env["is_root"] = os.geteuid() == 0
    except AttributeError:
        env["is_root"] = False

    # Windows admin check
    if env["is_windows"]:
        try:
            import ctypes
            env["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            env["is_admin"] = False

    # ============================================================
    # Capabilities probing
    # ============================================================

    # /proc/net/tcp readable?
    try:
        with open("/proc/net/tcp") as f:
            f.read(1)
        env["has_proc_net"] = True
    except (PermissionError, FileNotFoundError, IsADirectoryError, OSError):
        env["has_proc_net"] = False

    # /proc/[pid] readable?
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
        env["has_proc_pids"] = len(pids) > 0
    except Exception:
        env["has_proc_pids"] = False

    # Android pm command
    try:
        r = subprocess.run(["which", "pm"], capture_output=True, timeout=2)
        env["has_pm_command"] = r.returncode == 0
    except Exception:
        pass

    # Termux:API availability
    if env["is_termux"]:
        try:
            r = subprocess.run(
                ["timeout", "8", "termux-battery-status"],
                capture_output=True, text=True, timeout=12
            )
            env["has_termux_api"] = r.returncode == 0 and bool(r.stdout.strip())
        except Exception:
            env["has_termux_api"] = False

    # Desktop notifications
    if env["is_macos"]:
        env["has_desktop_notify"] = shutil.which("osascript") is not None
    elif env["is_linux"] and not env["is_termux"]:
        env["has_desktop_notify"] = (
            shutil.which("notify-send") is not None or
            shutil.which("zenity") is not None or
            shutil.which("powershell.exe") is not None  # WSL→Windows
        )
    elif env["is_windows"]:
        env["has_desktop_notify"] = True  # via powershell

    # phonenumbers library
    try:
        import phonenumbers  # noqa
        env["has_phonenumbers"] = True
    except ImportError:
        env["has_phonenumbers"] = False

    # Package manager
    for pm in ["apt", "apt-get", "apk", "dnf", "yum", "pacman",
               "brew", "choco", "winget", "scoop"]:
        try:
            r = subprocess.run(["which", pm], capture_output=True, timeout=2)
            if r.returncode == 0:
                env["has_pkg_manager"] = pm
                break
        except Exception:
            continue

    # ============================================================
    # Capabilities summary
    # ============================================================
    env["capabilities"] = {
        "process_triage": env["has_proc_pids"] or env["is_windows"],
        "network_triage": env["has_proc_net"] or env["is_windows"],
        "file_triage": True,
        "persistence_check": True,
        "android_osint": env["is_android"],
        "android_network": env["has_termux_api"],
        "android_spyware": env["has_termux_api"],
        "notifications": env["has_termux_api"] or env["has_desktop_notify"],
        "phone_osint": env["has_phonenumbers"],
        "system_logs": os.path.exists("/var/log") and os.access("/var/log", os.R_OK),
        "suid_scan": env["is_linux"] and not env["is_wsl"],
        "package_audit": env["has_pkg_manager"] is not None,
    }

    return env


def get_env_label(env):
    """Human-readable environment label."""
    if env["is_termux"]:
        return "Termux (Android)"
    if env["is_docker"]:
        return "Docker Container"
    if env["is_container"]:
        return "Container"
    if env["is_wsl"]:
        distro = os.environ.get("WSL_DISTRO_NAME", "WSL")
        return f"WSL ({distro})"
    if env["is_kali"]:
        return "Kali Linux"
    if env["is_linux"]:
        return "Linux"
    if env["is_macos"]:
        return "macOS"
    if env["is_windows"]:
        return f"Windows ({env['shell_type']})"
    return platform.system()


def print_env_info(env):
    """Print environment info banner."""
    label = get_env_label(env)

    print(f"\n[*] Environment:   {label}")
    print(f"[*] OS:            {env['os']} {env['release']}")
    print(f"[*] Platform:      {env['platform']}")
    print(f"[*] Python:        {env['python']}")
    print(f"[*] Machine:       {env['machine']}")

    # Privileges
    priv = "root" if env["is_root"] else "admin" if env["is_admin"] else "user"
    print(f"[*] Privileges:    {priv}")

    # Shell type
    if env["shell_type"]:
        print(f"[*] Shell:         {env['shell_type']}")

    # Package manager
    if env["has_pkg_manager"]:
        print(f"[*] Package mgr:   {env['has_pkg_manager']}")

    # Flags
    flags = []
    if env["is_termux"]:
        flags.append("termux")
    if env["is_docker"]:
        flags.append("docker")
    if env["is_wsl"]:
        flags.append("wsl")
    if env["is_kali"]:
        flags.append("kali")
    if env["has_termux_api"]:
        flags.append("termux-api")
    if env["has_desktop_notify"]:
        flags.append("desktop-notify")
    if env["has_phonenumbers"]:
        flags.append("phonenumbers")
    if flags:
        print(f"[*] Features:      {', '.join(flags)}")

    # Capabilities
    caps = env["capabilities"]
    available = [k for k, v in caps.items() if v]
    unavailable = [k for k, v in caps.items() if not v]

    if available:
        print(f"\n[✓] Available modules:")
        for cap in available:
            print(f"      - {cap}")
    if unavailable:
        print(f"\n[✗] Unavailable:")
        for cap in unavailable:
            print(f"      - {cap}")


if __name__ == "__main__":
    env = get_environment()
    print_env_info(env)
    import json
    print("\n--- Raw JSON ---")
    print(json.dumps(env, indent=2))
