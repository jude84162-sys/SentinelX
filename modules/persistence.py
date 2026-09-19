# modules/persistence.py
"""
SentinelX - Persistence Mechanism Detection
Finds startup scripts, cron jobs, and autostart entries.
"""

import os
import subprocess
import platform
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("SentinelX.persistence")


def _is_android():
    return "android" in platform.platform().lower()


def _run_cmd(cmd, timeout=5):
    """Run a shell command safely."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return None, "Timeout"
    except Exception as e:
        return None, str(e)


def _check_file(path, max_size=5000):
    """Check a file for suspicious content."""
    try:
        p = Path(path)
        if not p.exists() or not p.is_file():
            return None
        if p.stat().st_size > max_size:
            return {"path": str(p), "error": "File too large"}

        content = p.read_text(errors='ignore')
        return {
            "path": str(p),
            "size": p.stat().st_size,
            "modified": datetime.fromtimestamp(p.stat().st_mtime).isoformat(),
            "content_preview": content[:500],
            "has_suspicious": _has_suspicious_content(content)
        }
    except PermissionError:
        return {"path": str(path), "error": "Permission denied"}
    except Exception as e:
        return {"path": str(path), "error": str(e)}


def _has_suspicious_content(content):
    """Check for suspicious patterns in startup files."""
    patterns = [
        "curl ", "wget ", "nc ", "netcat", "ncat",
        "base64", "eval ", "exec ",
        "/dev/tcp/", "python -c", "bash -i",
        "chmod +x", ">/tmp/", "0<&", "sh -i"
    ]
    content_lower = content.lower()
    found = [p for p in patterns if p in content_lower]
    return found if found else None


def run_persistence_check():
    """Main persistence detection function."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "platform": platform.platform(),
        "is_android": _is_android(),
        "startup_files": [],
        "cron_jobs": [],
        "profile_d_scripts": [],
        "suspicious": [],
        "summary": {},
        "error": None
    }

    # Check startup files
    startup_files = [
        os.path.expanduser("~/.bashrc"),
        os.path.expanduser("~/.bash_profile"),
        os.path.expanduser("~/.profile"),
        os.path.expanduser("~/.zshrc"),
        os.path.expanduser("~/.config/fish/config.fish"),
    ]

    for f in startup_files:
        info = _check_file(f)
        if info and "error" not in info:
            result["startup_files"].append(info)
            if info.get("has_suspicious"):
                info["type"] = "startup_file"
                result["suspicious"].append(info)

    # Check cron jobs
    cron_output, cron_error = _run_cmd("crontab -l 2>/dev/null")
    if cron_output:
        result["cron_jobs"] = cron_output.split("\n")

    # Check $PREFIX/etc/profile.d/ (Termux specific)
    prefix = os.environ.get("PREFIX", "")
    if prefix:
        profile_d = Path(prefix) / "etc" / "profile.d"
        if profile_d.exists():
            try:
                for script in profile_d.iterdir():
                    if script.is_file():
                        info = _check_file(script)
                        if info and "error" not in info:
                            result["profile_d_scripts"].append(info)
                            if info.get("has_suspicious"):
                                info["type"] = "profile_d"
                                result["suspicious"].append(info)
            except PermissionError:
                result["error"] = "Cannot read profile.d directory"

    # Android-specific checks (limited without root)
    if _is_android():
        android_paths = [
            "/data/data/com.termux/files/usr/etc/profile.d",
            "/sdcard/.termux",
        ]
        for path in android_paths:
            info = _check_file(path) if Path(path).is_file() else None
            if info and "error" not in info:
                result["startup_files"].append(info)

    result["summary"] = {
        "startup_files_checked": len(result["startup_files"]),
        "cron_jobs": len(result["cron_jobs"]),
        "profile_d_scripts": len(result["profile_d_scripts"]),
        "suspicious": len(result["suspicious"])
    }

    if _is_android():
        result["warning"] = (
            "Android persistence mechanisms are largely hidden without root. "
            "This scan covers Termux-level persistence only."
        )

    return result


def print_persistence_report(result):
    """Print the persistence report."""
    print("\n" + "=" * 70)
    print("  Persistence Detection Report - SentinelX")
    print("=" * 70)

    s = result.get("summary", {})
    print(f"\n[*] Startup files checked: {s.get('startup_files_checked', 0)}")
    print(f"[*] Cron jobs: {s.get('cron_jobs', 0)}")
    print(f"[*] Profile.d scripts: {s.get('profile_d_scripts', 0)}")
    print(f"[*] Suspicious: {s.get('suspicious', 0)}")

    if result.get("warning"):
        print(f"\n[!] {result['warning']}")

    if result.get("suspicious"):
        print("\n[!] Suspicious persistence entries:")
        for item in result["suspicious"]:
            print(f"    ⚠ {item['path']} ({item.get('type', 'unknown')})")
            if item.get("has_suspicious"):
                print(f"       Patterns: {', '.join(item['has_suspicious'])}")

    if result.get("cron_jobs"):
        print("\n[*] Cron jobs:")
        for job in result["cron_jobs"]:
            if job and not job.startswith("#"):
                print(f"    • {job}")

    if result.get("startup_files"):
        print("\n[*] Startup files found:")
        for f in result["startup_files"][:5]:
            print(f"    • {f['path']} ({f['size']} bytes)")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    r = run_persistence_check()
    print_persistence_report(r)
