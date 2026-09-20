# modules/self_update.py
"""
SentinelX - Self Update
Checks GitHub for new releases and updates from git.
"""

import os
import json
import logging
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

logger = logging.getLogger("SentinelX.update")

BASE_DIR = Path(__file__).parent.parent
REPO = "jude84162-sys/SentinelX"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"

# Current version - keep in sync with SentinelX.py
CURRENT_VERSION = "1.3.0"


def get_latest_version():
    """Get latest version tag from GitHub."""
    try:
        req = urllib.request.Request(
            API_URL,
            headers={
                "User-Agent": "SentinelX/1.0",
                "Accept": "application/vnd.github+json",
            }
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
            tag = data.get("tag_name", "")
            return tag.lstrip("v")
    except urllib.error.HTTPError as e:
        logger.debug(f"GitHub API HTTP {e.code}")
        return None
    except Exception as e:
        logger.debug(f"Update check failed: {e}")
        return None


def compare_versions(current, latest):
    """Return: -1 if current < latest, 0 if equal, 1 if current > latest."""
    def parse(v):
        try:
            return tuple(int(x) for x in v.split("."))
        except Exception:
            return (0,)

    c = parse(current)
    l = parse(latest)

    if c < l:
        return -1
    if c > l:
        return 1
    return 0


def check_for_update():
    """Check if update is available."""
    latest = get_latest_version()

    if not latest:
        return {
            "status": "error",
            "message": "Could not reach GitHub",
            "current": CURRENT_VERSION,
        }

    cmp = compare_versions(CURRENT_VERSION, latest)

    if cmp == 0:
        return {
            "status": "current",
            "version": CURRENT_VERSION,
        }
    elif cmp < 0:
        return {
            "status": "available",
            "current": CURRENT_VERSION,
            "latest": latest,
        }
    else:
        return {
            "status": "ahead",
            "current": CURRENT_VERSION,
            "latest": latest,
            "message": "You're running a dev version",
        }


def update():
    """Pull latest changes from GitHub."""
    if not (BASE_DIR / ".git").exists():
        return {
            "status": "error",
            "message": "Not a git repository. Cannot auto-update.",
        }

    try:
        # Check for local changes
        result = subprocess.run(
            ["git", "-C", str(BASE_DIR), "status", "--porcelain"],
            capture_output=True, text=True, timeout=10
        )

        if result.stdout.strip():
            return {
                "status": "error",
                "message": "You have local changes. Commit or stash them first:\n"
                           "  cd ~/SentinelX && git stash",
            }

        # Pull
        result = subprocess.run(
            ["git", "-C", str(BASE_DIR), "pull", "origin", "main"],
            capture_output=True, text=True, timeout=60
        )

        if result.returncode == 0:
            return {
                "status": "success",
                "output": result.stdout.strip(),
            }

        return {
            "status": "error",
            "message": result.stderr.strip() or "git pull failed",
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Update timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def print_update_status():
    """Print update check result."""
    print("\n" + "=" * 70)
    print("  SentinelX Update Check")
    print("=" * 70)

    r = check_for_update()
    status = r.get("status", "unknown")

    if status == "error":
        print(f"\n[!] {r['message']}")
        print(f"    Current version: v{r.get('current', '?')}")

    elif status == "current":
        print(f"\n[✓] You are up to date")
        print(f"    Version: v{r['version']}")

    elif status == "available":
        print(f"\n[!] Update available!")
        print(f"    Current:  v{r['current']}")
        print(f"    Latest:   v{r['latest']}")
        print(f"\n[*] To update:")
        print(f"    cd ~/SentinelX && git pull")
        print(f"\n[*] Or use:")
        print(f"    python -m modules.self_update --update")

    elif status == "ahead":
        print(f"\n[i] {r['message']}")
        print(f"    Current: v{r['current']}")
        print(f"    GitHub:  v{r['latest']}")

    print("\n" + "=" * 70 + "\n")


def do_update_and_print():
    """Perform update and print result."""
    print("\n" + "=" * 70)
    print("  SentinelX Update")
    print("=" * 70)

    result = update()
    status = result.get("status")

    if status == "success":
        print(f"\n[✓] Updated successfully!")
        if result.get("output"):
            print(f"\n{result['output']}")
        print(f"\n[*] Restart SentinelX to use new version")

    elif status == "error":
        print(f"\n[!] Update failed:")
        print(f"    {result['message']}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        do_update_and_print()
    else:
        print_update_status()
