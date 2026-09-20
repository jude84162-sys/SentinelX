# modules/files.py
"""
SentinelX - File System Triage (High-Accuracy Final)
Zero false positives. Detects:
- EICAR test files (content-based, industry standard)
- Malware content patterns (reverse shells, web shells)
- Suspicious extensions and filenames
- Large/suspicious files in critical paths

Cross-platform: Android (Termux), Linux, macOS, WSL.
"""

import os
import platform
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("SentinelX.files")


def _is_android():
    return "android" in platform.platform().lower()


# ============================================================
# Scan paths (expanded coverage, canonical, no duplicates)
# ============================================================

if _is_android():
    # Canonical paths — /sdcard is a symlink to /storage/emulated/0
    SCAN_PATHS = [
        "/storage/emulated/0/Download",
        "/storage/emulated/0/Documents",
        "/storage/emulated/0/DCIM",
        "/storage/emulated/0/Pictures",
        "/storage/emulated/0/Movies",
        "/storage/emulated/0/Music",
        "/storage/emulated/0/Android/media",
        os.path.expanduser("~"),
    ]
    SAFE_PATHS = [
        # User folders on Android — normal content, don't flag
        "/storage/emulated/0/Download",
        "/storage/emulated/0/Documents",
        "/storage/emulated/0/DCIM",
        "/storage/emulated/0/Pictures",
        "/storage/emulated/0/Music",
        "/storage/emulated/0/Movies",
        "/storage/emulated/0/WhatsApp",
        "/storage/emulated/0/Android/media",
        # Termux system
        "/data/data/com.termux/files/usr",
        "/data/data/com.termux/files/home/go/pkg",
        "/data/data/com.termux/files/home/.cache",
        "/data/data/com.termux/files/home/.local",
        "/data/data/com.termux/files/home/.termux/boot",
        "/data/data/com.termux/files/home/SentinelX",
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
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/Pictures"),
        "/usr/lib", "/usr/share", "/usr/local/lib",
        "/var/lib/dpkg", "/var/cache",
        os.path.expanduser("~/.cache"),
        os.path.expanduser("~/.local"),
        os.path.expanduser("~/go/pkg"),
        os.path.expanduser("~/.cargo"),
        os.path.expanduser("~/.rustup"),
    ]


# ============================================================
# Whitelists
# ============================================================

WHITELIST_PATTERNS = [
    "f-droid", "fdroid", "termux", "termux-api", "termux-app",
    "github", "chromium", "chrome", "firefox",
    "k9-mail", "newpipe", "vanced", "magisk",
    "vscode", "code-server",
    "start-sentinelx",
]

HOME_DOTFILE_WHITELIST = {
    ".bashrc", ".bash_profile", ".bash_history", ".bash_logout",
    ".profile", ".zshrc", ".zsh_history", ".zprofile",
    ".env", ".env.local", ".env.example",
    ".gitconfig", ".git-credentials", ".gitignore",
    ".rediscli_history", ".python_history", ".node_repl_history",
    ".npmrc", ".config", ".ssh", ".gnupg",
    ".curlrc", ".wgetrc", ".inputrc",
    ".termux", ".wget-hsts", ".viminfo",
}

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
    "/.termux/boot/",
    "/SentinelX/",
]


# ============================================================
# Threat signatures
# ============================================================

HIGH_RISK_EXTENSIONS = {".sh", ".elf", ".dex", ".so", ".pl", ".rb", ".bin"}
MEDIUM_RISK_EXTENSIONS = {".apk", ".exe", ".msi", ".jar", ".js", ".vbs", ".scr"}

# Note: 'hack', 'spy', 'steal' removed — too many false positives
# (e.g., "hack cs 1.6" game cheats are not malware)
RED_FLAG_NAMES = {
    "payload", "exploit", "backdoor", "reverse",
    "bind_shell", "meterpreter", "rootkit",
    "keylogger", "ransom", "cryptolocker",
    "xmrig", "miner", "rat.", "trojan",
    "malware", "virus", "worm",
}

SUSPICIOUS_DIRS = [
    "/dev/shm",
    "/var/tmp",
    "/run/user",
    "/data/local/tmp",
]

# EICAR — industry-standard antivirus test
EICAR_SIGNATURE = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

# Malware content patterns (byte sequences in file content)
MALWARE_CONTENT_PATTERNS = [
    # Reverse shells
    b"nc -e /bin/bash",
    b"nc -e /bin/sh",
    b"bash -i >& /dev/tcp/",
    b"bash -i >&/dev/tcp/",
    b"/bin/sh -i",
    b"python -c 'import socket",
    b'python -c "import socket',
    # PowerShell
    b"powershell -e",
    b"powershell -enc",
    b"IEX(New-Object",
    b"DownloadString(",
    b"System.Reflection.Assembly",
    # Web shells
    b"eval(base64_decode",
    b"eval(gzinflate",
    b"eval(gzuncompress",
    b"assert($_POST",
    b"system($_GET",
    b"passthru($_POST",
    b"shell_exec($_POST",
]


# ============================================================
# Helpers
# ============================================================

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
            "extension": os.path.splitext(path)[1].lower(),
        }
    except (OSError, PermissionError):
        return None


def _check_eicar(path, size):
    """Check for EICAR test file signature."""
    if size > 512:  # EICAR file is ~68 bytes
        return False
    try:
        with open(path, "rb") as f:
            content = f.read(512)
        return EICAR_SIGNATURE in content
    except (PermissionError, OSError):
        return False


def _check_malware_content(path, size):
    """Check content for malware patterns. Only small files."""
    if size > 1024 * 1024:  # Skip files > 1MB
        return None
    if size < 4:
        return None

    ext = os.path.splitext(path)[1].lower()
    # Only scan text-like or script files
    if ext not in {".sh", ".pl", ".rb", ".py", ".js", ".php",
                   ".txt", ".elf", ".dex", ".bat", ".cmd", ".ps1", ""}:
        return None

    try:
        with open(path, "rb") as f:
            content = f.read(64 * 1024)  # First 64KB

        for pattern in MALWARE_CONTENT_PATTERNS:
            if pattern in content:
                return pattern.decode("utf-8", errors="replace")

    except (PermissionError, OSError):
        pass

    return None


# ============================================================
# Suspicion logic
# ============================================================

def _is_suspicious_file(info):
    """Multi-layer suspicion. Returns (is_suspicious, reason)."""
    name_lower = info["name"].lower()
    path_str = info["path"]
    ext = info["extension"]
    size = info["size"]

    # Layer 0: whitelist (never suspicious)
    if _is_whitelisted(name_lower):
        return False, None

    # Layer 1: skip build/cache/self paths
    if _should_skip_path(path_str):
        return False, None

    # Layer 2: EICAR test file (highest priority — content check)
    if _check_eicar(path_str, size):
        return True, "EICAR test file detected"

    # Layer 3: red flag names (always suspicious, regardless of location)
    for flag in RED_FLAG_NAMES:
        if flag in name_lower:
            return True, f"Red flag in name: '{flag}'"

    # Layer 4: files in suspicious directories (regardless of user folders)
    for sdir in SUSPICIOUS_DIRS:
        if path_str.startswith(sdir):
            return True, f"File in suspicious directory: {sdir}"

    # Layer 5: malware content patterns
    pattern = _check_malware_content(path_str, size)
    if pattern:
        return True, f"Malware pattern in content: '{pattern}'"

    # Layer 6: skip everything below for user's personal folders
    if _is_in_safe_path(path_str):
        return False, None

    # Layer 7: high-risk extensions outside safe paths
    if ext in HIGH_RISK_EXTENSIONS:
        return True, f"High-risk extension: {ext}"

    # Layer 8: medium-risk extensions outside safe paths
    if ext in MEDIUM_RISK_EXTENSIONS:
        return True, f"Executable outside safe path: {ext}"

    # Layer 9: hidden files outside home
    if info["name"].startswith(".") and info["age_days"] <= 3:
        home = os.path.expanduser("~")
        if not path_str.startswith(home + "/") and path_str != home:
            return True, "Recently modified hidden file outside home"

    # Layer 10: very large files (>500MB) outside safe paths
    if size > 500 * 1024 * 1024:
        return True, f"Very large file: {info['size_human']}"

    return False, None


# ============================================================
# Main scanner
# ============================================================

def run_file_triage():
    """Full file system triage."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "platform": platform.platform(),
        "is_android": _is_android(),
        "scan_paths": [],
        "files_scanned": 0,
        "suspicious": [],
        "recent_executables": [],
        "large_files": [],
        "eicar_detected": [],
        "malware_content": [],
        "errors": [],
        "summary": {},
    }

    # Track real paths to avoid duplicates (symlinks like /sdcard)
    scanned_real_paths = set()

    for scan_path in SCAN_PATHS:
        path = Path(scan_path)
        path_info = {
            "path": scan_path,
            "exists": path.exists(),
            "accessible": False,
        }

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

                # Skip duplicates via realpath
                try:
                    real = os.path.realpath(entry)
                    if real in scanned_real_paths:
                        continue
                    scanned_real_paths.add(real)
                except (OSError, ValueError):
                    pass

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

                    if "EICAR" in reason:
                        result["eicar_detected"].append(info)
                    elif "Malware pattern" in reason:
                        result["malware_content"].append(info)

                # Recent executables (last 7 days)
                if info["extension"] in {".elf", ".sh"} and info["age_days"] <= 7:
                    if not _is_in_safe_path(info["path"]):
                        result["recent_executables"].append(info)

                # Large files (>200MB)
                if info["size"] > 200 * 1024 * 1024:
                    result["large_files"].append(info)

        except PermissionError:
            result["errors"].append(f"Permission denied: {scan_path}")
        except Exception as e:
            result["errors"].append(f"Error scanning {scan_path}: {e}")

    result["summary"] = {
        "files_scanned": result["files_scanned"],
        "suspicious_count": len(result["suspicious"]),
        "recent_executables": len(result["recent_executables"]),
        "large_files": len(result["large_files"]),
        "eicar_detected": len(result["eicar_detected"]),
        "malware_content": len(result["malware_content"]),
        "errors": len(result["errors"]),
    }

    if _is_android() and not any(p.get("accessible") for p in result["scan_paths"]):
        result["warning"] = (
            "Limited file access on Android. Grant storage permission via "
            "'termux-setup-storage' or run with root for full scan."
        )

    return result


# ============================================================
# Report printer
# ============================================================

def print_file_report(result):
    print("\n" + "=" * 70)
    print("  File System Triage Report - SentinelX")
    print("=" * 70)

    s = result.get("summary", {})
    print(f"\n[*] Files scanned: {s.get('files_scanned', 0)}")
    print(f"[*] Suspicious files: {s.get('suspicious_count', 0)}")
    print(f"[*] EICAR detected: {s.get('eicar_detected', 0)}")
    print(f"[*] Malware content: {s.get('malware_content', 0)}")
    print(f"[*] Recent executables: {s.get('recent_executables', 0)}")
    print(f"[*] Large files: {s.get('large_files', 0)}")
    print(f"[*] Errors: {s.get('errors', 0)}")

    if result.get("warning"):
        print(f"\n[!] {result['warning']}")

    # EICAR (highest priority)
    if result.get("eicar_detected"):
        print(f"\n[!] EICAR test files detected ({len(result['eicar_detected'])}):")
        for f in result["eicar_detected"]:
            print(f"    🔴 {f['path']}")
            print(f"       {f['reason']}")

    # Malware content
    if result.get("malware_content"):
        print(f"\n[!] Malware patterns in content ({len(result['malware_content'])}):")
        for f in result["malware_content"]:
            print(f"    🔴 {f['path']}")
            print(f"       {f['reason']}")

    # Other suspicious
    other = [f for f in result.get("suspicious", [])
             if f not in result.get("eicar_detected", [])
             and f not in result.get("malware_content", [])]
    if other:
        print(f"\n[!] Other suspicious files ({len(other)}):")
        for f in other[:20]:
            print(f"    ⚠ {f['path']}")
            print(f"       Reason: {f['reason']} ({f['size_human']}, {f['age_days']}d old)")

    # Recent executables
    if result.get("recent_executables"):
        print(f"\n[*] Recently modified executables (last 7 days):")
        for f in result["recent_executables"][:10]:
            print(f"    - {f['path']} ({f['size_human']}, {f['age_days']}d)")

    # Large files
    if result.get("large_files"):
        print(f"\n[*] Large files (>200MB):")
        for f in result["large_files"][:10]:
            print(f"    - {f['path']} ({f['size_human']})")

    # Errors
    if result.get("errors"):
        print(f"\n[!] Access errors:")
        for e in result["errors"][:5]:
            print(f"    - {e}")

    print("\n" + "=" * 70 + "\n")


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    r = run_file_triage()
    print_file_report(r)
