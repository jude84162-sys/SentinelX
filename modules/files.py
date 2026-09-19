# modules/files.py
"""SentinelX - File System Triage (Smart heuristics, cross-platform)"""

import os
import platform
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("SentinelX.files")


def _is_android():
    return "android" in platform.platform().lower()


if _is_android():
    SCAN_PATHS = [
        "/sdcard/Download",
        "/sdcard/Documents",
        os.path.expanduser("~"),
    ]
    SAFE_PATHS = [
        "/sdcard/Download",
        "/sdcard/Documents",
        "/data/data/com.termux/files/usr",
        "/data/data/com.termux/files/home/go/pkg",
        "/data/data/com.termux/files/home/.cache",
        "/data/data/com.termux/files/home/.local",
        "/data/data/com.termux/files/home/psutil-",
    ]
else:
    SCAN_PATHS = [
        os.path.expanduser("~"),
        "/tmp",
        "/var/tmp",
        "/dev/shm",
    ]
    SAFE_PATHS = [
        os.path.expanduser("~/Downloads"),
        "/usr/lib", "/usr/share", "/usr/local/lib",
        "/var/lib/dpkg", "/var/cache",
        os.path.expanduser("~/.cache"),
        os.path.expanduser("~/.local"),
        os.path.expanduser("~/go/pkg"),
        os.path.expanduser("~/.cargo"),
        os.path.expanduser("~/.rustup"),
    ]

WHITELIST_PATTERNS = [
    "f-droid", "fdroid", "termux", "termux-api", "termux-app",
    "github", "chromium", "chrome", "firefox",
    "k9-mail", "newpipe", "vanced", "magisk",
    "vscode", "code-server",
]

# Dotfiles that are always legit in home
HOME_DOTFILE_WHITELIST = {
    ".bashrc", ".bash_profile", ".bash_history", ".bash_logout",
    ".profile", ".zshrc", ".zsh_history", ".zprofile",
    ".env", ".env.local", ".env.example",
    ".gitconfig", ".git-credentials", ".gitignore",
    ".rediscli_history", ".python_history", ".node_repl_history",
    ".npmrc", ".config", ".ssh", ".gnupg",
    ".curlrc", ".wgetrc", ".inputrc",
}

# Paths that are never interesting (build caches, package managers)
SKIP_PATH_FRAGMENTS = [
    "/go/pkg/mod/",
    "/node_modules/",
    "/site-packages/",
    "/.cache/",
    "/psutil-",
    "/pip-build-",
    "/pip-install-",
    "/.cargo/registry/",
    "/.rustup/",
    "/.npm/",
    "/.local/lib/",
    "/venv/",
    "/.venv/",
    "/__pycache__/",
]

HIGH_RISK_EXTENSIONS = {".sh", ".elf", ".dex", ".so", ".pl", ".rb", ".bin"}
MEDIUM_RISK_EXTENSIONS = {".apk", ".exe", ".msi", ".jar", ".js", ".vbs", ".scr"}

RED_FLAG_NAMES = {
    "payload", "exploit", "backdoor", "reverse",
    "bind_shell", "meterpreter", "rootkit",
    "keylogger", "ransom", "cryptolocker",
    "xmrig", "miner", "rat.", "trojan"
}

SUSPICIOUS_DIRS = [
    "/dev/shm",
    "/var/tmp",
    "/run/user",
]


def _is_in_safe_path(path):
    path_str = str(path)
    return any(path_str.startswith(safe) for safe in SAFE_PATHS)


def _should_skip_path(path_str):
    return any(frag in path_str for frag in SKIP_PATH_FRAGMENTS)


def _is_whitelisted(name):
    name_lower = name.lower()
    if name_lower in HOME_DOTFILE_WHITELIST:
        return True
    return any(p in name_lower for p in WHITELIST_PATTERNS)


def _human_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _get_file_info(path):
    try:
        stat = os.stat(path)
        return {
            "path": str(path),
            "name": os.path.basename(path),
            "size": stat.st_size,
            "size_human": _human_size(stat.st_size),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "age_days": (datetime.now() - datetime.fromtimestamp(stat.st_mtime)).days,
            "extension": os.path.splitext(path)[1].lower()
        }
    except (OSError, PermissionError):
        return None


def _is_suspicious_file(info):
    name_lower = info["name"].lower()
    path_str = info["path"]
    ext = info["extension"]

    # 1. Whitelist check — never suspicious
    if _is_whitelisted(name_lower):
        return False, None

    # 2. Skip build/cache dirs
    if _should_skip_path(path_str):
        return False, None

    # 3. Red flag names — always suspicious
    for flag in RED_FLAG_NAMES:
        if flag in name_lower:
            return True, f"Red flag in name: {flag}"

    # 4. Files in suspicious directories
    for sdir in SUSPICIOUS_DIRS:
        if path_str.startswith(sdir):
            return True, f"File in suspicious directory: {sdir}"

    # 5. High-risk extensions — suspicious outside safe paths
    if ext in HIGH_RISK_EXTENSIONS:
        if not _is_in_safe_path(path_str):
            return True, f"High-risk extension: {ext}"

    # 6. Medium-risk extensions
    if ext in MEDIUM_RISK_EXTENSIONS:
        if not _is_in_safe_path(path_str):
            return True, f"Executable outside safe path: {ext}"

    # 7. Hidden files — only outside home dir
    if info["name"].startswith(".") and info["age_days"] <= 3:
        home = os.path.expanduser("~")
        if not path_str.startswith(home + "/") and path_str != home:
            if not _is_in_safe_path(path_str):
                return True, "Recently modified hidden file outside home"

    # 8. Very large files (>500MB) outside safe paths
    if info["size"] > 500 * 1024 * 1024:
        if not _is_in_safe_path(path_str):
            return True, f"Very large file: {info['size_human']}"

    return False, None


def run_file_triage():
    result = {
        "timestamp": datetime.now().isoformat(),
        "platform": platform.platform(),
        "is_android": _is_android(),
        "scan_paths": [],
        "files_scanned": 0,
        "suspicious": [],
        "recent_executables": [],
        "large_files": [],
        "errors": [],
        "summary": {}
    }

    for scan_path in SCAN_PATHS:
        path = Path(scan_path)
        path_info = {"path": scan_path, "exists": path.exists(), "accessible": False}

        if not path.exists():
            result["scan_paths"].append(path_info)
            continue

        try:
            list(path.iterdir())
            path_info["accessible"] = True
        except PermissionError:
            path_info["error"] = "Permission denied"
            result["errors"].append(f"Cannot access {scan_path}")
            result["scan_paths"].append(path_info)
            continue

        result["scan_paths"].append(path_info)

        try:
            for entry in path.rglob("*"):
                if not entry.is_file():
                    continue

                entry_str = str(entry)
                if _should_skip_path(entry_str):
                    continue

                try:
                    info = _get_file_info(entry)
                    if not info:
                        continue
                except Exception:
                    continue

                result["files_scanned"] += 1

                suspicious, reason = _is_suspicious_file(info)
                if suspicious:
                    info["reason"] = reason
                    result["suspicious"].append(info)

                if info["extension"] in {".elf", ".sh"} and info["age_days"] <= 7:
                    if not _is_in_safe_path(info["path"]):
                        result["recent_executables"].append(info)

                if info["size"] > 200 * 1024 * 1024:
                    result["large_files"].append(info)

        except PermissionError:
            result["errors"].append(f"Permission denied: {scan_path}")
        except Exception as e:
            result["errors"].append(f"Error: {scan_path}: {e}")

    result["summary"] = {
        "files_scanned": result["files_scanned"],
        "suspicious_count": len(result["suspicious"]),
        "recent_executables": len(result["recent_executables"]),
        "large_files": len(result["large_files"]),
        "errors": len(result["errors"])
    }

    if _is_android() and not any(p.get("accessible") for p in result["scan_paths"]):
        result["warning"] = (
            "Limited file access on Android. Grant storage permission via "
            "'termux-setup-storage' or run with root for full scan."
        )

    return result


def print_file_report(result):
    print("\n" + "=" * 70)
    print("  File System Triage Report - SentinelX")
    print("=" * 70)

    s = result.get("summary", {})
    print(f"\n[*] Files scanned: {s.get('files_scanned', 0)}")
    print(f"[*] Suspicious files: {s.get('suspicious_count', 0)}")
    print(f"[*] Recent executables: {s.get('recent_executables', 0)}")
    print(f"[*] Large files: {s.get('large_files', 0)}")
    print(f"[*] Errors: {s.get('errors', 0)}")

    if result.get("warning"):
        print(f"\n[!] {result['warning']}")

    if result.get("suspicious"):
        print("\n[!] Suspicious files (HIGH CONFIDENCE):")
        for f in result["suspicious"][:15]:
            print(f"    [!] {f['path']}")
            print(f"        Reason: {f['reason']} ({f['size_human']}, {f['age_days']}d old)")

    if result.get("recent_executables"):
        print("\n[*] Recently modified executables (last 7 days):")
        for f in result["recent_executables"][:10]:
            print(f"    - {f['path']} ({f['size_human']}, {f['age_days']}d)")

    if result.get("large_files"):
        print("\n[*] Large files (>200MB):")
        for f in result["large_files"][:10]:
            print(f"    - {f['path']} ({f['size_human']})")

    if result.get("errors"):
        print("\n[!] Access errors:")
        for e in result["errors"][:5]:
            print(f"    - {e}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    r = run_file_triage()
    print_file_report(r)
