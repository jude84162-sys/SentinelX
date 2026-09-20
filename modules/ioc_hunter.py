# modules/ioc_hunter.py
"""
SentinelX - IOC Hunter (Geo-Unrestricted)
Hash-based malware detection using SHA-256 signatures.

Uses abuse.ch EXPORT FILES (not APIs) — these work from any region:
- bazaar.abuse.ch/export/txt/sha256/recent/  → Recent malware hashes
- urlhaus.abuse.ch/downloads/text/            → Malware URLs

Plus local database for user IOCs.

Fetcher uses curl (more reliable than urllib on Termux).
"""

import os
import json
import re
import hashlib
import logging
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger("SentinelX.ioc_hunter")

BASE_DIR = Path(__file__).parent.parent
IOC_DIR = BASE_DIR / "iocs"
IOC_DIR.mkdir(exist_ok=True)

LOCAL_IOC_FILE = IOC_DIR / "local_hashes.json"
ONLINE_CACHE_FILE = IOC_DIR / "online_cache.json"
CACHE_TTL_HOURS = 6


# ============================================================
# Built-in hashes (always available)
# ============================================================

BUILTIN_IOC_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c": "WannaCry.Ransomware",
    "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745": "NotPetya.Ransomware",
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": "WannaCry.Variant.B",
}


# ============================================================
# abuse.ch export sources (geo-unrestricted)
# ============================================================

ABUSE_CH_SOURCES = [
    {
        "name": "MalwareBazaar-Recent",
        "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "type": "sha256_list",
        "description": "Recent malware samples (~1000 hashes)",
    },
]


# ============================================================
# Fetcher (curl-based for reliability on Termux)
# ============================================================

def _fetch_url(url, timeout=30):
    """
    Fetch URL content.
    Uses curl if available (more reliable TLS on Termux),
    falls back to urllib.
    """
    # Try curl first
    try:
        result = subprocess.run(
            [
                "curl", "-sL", "--max-time", str(timeout),
                "-H", "User-Agent: Mozilla/5.0 (X11; Linux x86_64) SentinelX/1.0",
                "-H", "Accept: text/plain,*/*",
                url
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 5
        )

        if result.returncode == 0 and result.stdout:
            return result.stdout
        elif result.stderr:
            logger.debug(f"curl error: {result.stderr.strip()[:100]}")

    except FileNotFoundError:
        logger.debug("curl not available, trying urllib")
    except subprocess.TimeoutExpired:
        logger.debug(f"curl timeout for {url}")
    except Exception as e:
        logger.debug(f"curl failed: {e}")

    # Fallback: urllib
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) SentinelX/1.0",
                "Accept": "text/plain,*/*",
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        logger.debug(f"HTTP {e.code}: {url}")
    except Exception as e:
        logger.debug(f"urllib failed: {e}")

    return None


# ============================================================
# Parsers
# ============================================================

def _parse_sha256_list(content, threat_prefix="MalwareBazaar"):
    """
    Parse list of SHA256 hashes.
    Format: one 64-char hex hash per line, # for comments.
    """
    hashes = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Check for SHA256 hash
        if len(line) == 64 and re.match(r"^[a-f0-9]{64}$", line.lower()):
            hashes[line.lower()] = f"{threat_prefix}:Malware"

    return hashes


# ============================================================
# Online IOC fetching
# ============================================================

def fetch_abusech_iocs():
    """Fetch IOCs from abuse.ch export files."""
    all_hashes = {}

    for source in ABUSE_CH_SOURCES:
        name = source["name"]
        url = source["url"]

        logger.info(f"  Fetching {name}...")
        content = _fetch_url(url)

        if not content:
            logger.warning(f"    ✗ {name}: no response")
            continue

        hashes = _parse_sha256_list(content, threat_prefix=name)

        if hashes:
            logger.info(f"    ✓ {name}: {len(hashes)} hashes")
            all_hashes.update(hashes)
        else:
            logger.warning(f"    ✗ {name}: no hashes parsed ({len(content)} bytes)")

    return all_hashes


# ============================================================
# Local IOC management
# ============================================================

def load_local_iocs():
    """Load built-in + user IOCs from local file."""
    hashes = dict(BUILTIN_IOC_HASHES)

    if LOCAL_IOC_FILE.exists():
        try:
            user_hashes = json.load(open(LOCAL_IOC_FILE))
            user_hashes = {k.lower(): v for k, v in user_hashes.items()}
            hashes.update(user_hashes)
            logger.info(f"Loaded {len(user_hashes)} user IOCs")
        except Exception as e:
            logger.debug(f"Failed to load user IOCs: {e}")

    return hashes


def add_ioc(sha256_hash, threat_name):
    """Add a new IOC to local database."""
    current = {}
    if LOCAL_IOC_FILE.exists():
        try:
            current = json.load(open(LOCAL_IOC_FILE))
        except Exception:
            pass

    current[sha256_hash.lower()] = threat_name

    with open(LOCAL_IOC_FILE, "w") as f:
        json.dump(current, f, indent=2)

    return True


# ============================================================
# Online IOC cache
# ============================================================

def load_online_iocs():
    """Load online IOCs from cache or fetch fresh."""
    # Check cache first
    if ONLINE_CACHE_FILE.exists():
        try:
            data = json.load(open(ONLINE_CACHE_FILE))
            cached_at = datetime.fromisoformat(data.get("cached_at", "1970-01-01"))
            age = datetime.now() - cached_at

            if age < timedelta(hours=CACHE_TTL_HOURS):
                count = len(data.get("hashes", {}))
                if count > 0:
                    hours_old = age.total_seconds() / 3600
                    logger.info(f"Using cached IOCs ({count} hashes, {hours_old:.1f}h old)")
                    return data.get("hashes", {})
        except Exception:
            pass

    # Fetch fresh
    logger.info("Fetching fresh IOCs from abuse.ch export files...")
    hashes = fetch_abusech_iocs()

    if hashes:
        try:
            with open(ONLINE_CACHE_FILE, "w") as f:
                json.dump({
                    "cached_at": datetime.now().isoformat(),
                    "count": len(hashes),
                    "hashes": hashes,
                }, f)
            logger.info(f"Cached {len(hashes)} online IOCs")
        except Exception as e:
            logger.debug(f"Cache write failed: {e}")
    else:
        logger.warning("No online IOCs fetched — using local only")

    return hashes


# ============================================================
# Hashing
# ============================================================

def calculate_sha256(filepath, max_size=100 * 1024 * 1024):
    """Calculate SHA-256 hash (skips large files)."""
    try:
        size = os.path.getsize(filepath)
        if size > max_size:
            return None

        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError):
        return None


# ============================================================
# Scanning
# ============================================================

def scan_path(target_path, use_online=True, max_file_size=100 * 1024 * 1024):
    """Scan a file or directory for known malware hashes."""
    local_iocs = load_local_iocs()
    online_iocs = load_online_iocs() if use_online else {}
    all_iocs = {**online_iocs, **local_iocs}

    logger.info(f"IOC database size: {len(all_iocs)} hashes")

    matches = []
    scanned = 0
    skipped = 0
    errors = 0

    if os.path.isfile(target_path):
        files = [target_path]
    else:
        files = []
        for root, dirs, filenames in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in (
                "__pycache__", "node_modules", ".git", ".cache",
                ".venv", "venv", "go", ".cargo",
            )]
            for f in filenames:
                files.append(os.path.join(root, f))

    for filepath in files:
        try:
            size = os.path.getsize(filepath)
            if size > max_file_size:
                skipped += 1
                continue

            file_hash = calculate_sha256(filepath)
            if not file_hash:
                errors += 1
                continue

            scanned += 1

            if file_hash in all_iocs:
                threat = all_iocs[file_hash]
                logger.warning(f"MALWARE: {filepath} → {threat}")
                matches.append({
                    "path": filepath,
                    "sha256": file_hash,
                    "threat": threat,
                    "size": size,
                    "detected_at": datetime.now().isoformat(),
                })

        except (OSError, PermissionError):
            errors += 1
            continue

    return {
        "target": target_path,
        "scanned": scanned,
        "skipped": skipped,
        "errors": errors,
        "matches": matches,
        "ioc_count": len(all_iocs),
    }


# ============================================================
# Report
# ============================================================

def print_ioc_report(result):
    print("\n" + "=" * 70)
    print("  IOC Hunter Report - SentinelX")
    print("=" * 70)

    print(f"\n[*] Target: {result.get('target')}")
    print(f"[*] Files scanned: {result.get('scanned', 0)}")
    print(f"[*] Files skipped: {result.get('skipped', 0)}")
    print(f"[*] Errors: {result.get('errors', 0)}")
    print(f"[*] IOC database size: {result.get('ioc_count', 0)}")
    print(f"[*] Matches: {len(result.get('matches', []))}")

    matches = result.get("matches", [])
    if matches:
        print(f"\n[!] Malware detected:")
        for m in matches:
            print(f"\n    🔴 {m['path']}")
            print(f"       Threat: {m['threat']}")
            print(f"       SHA-256: {m['sha256']}")
            print(f"       Size: {m['size']} bytes")
    else:
        print(f"\n[✓] No IOC matches")

    print("\n" + "=" * 70 + "\n")


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
    )

    if len(sys.argv) < 2:
        print("Usage: python -m modules.ioc_hunter <path>")
        print("       python -m modules.ioc_hunter ~/storage/shared/Download")
        sys.exit(1)

    target = os.path.expanduser(sys.argv[1])
    if not os.path.exists(target):
        print(f"Error: {target} not found")
        sys.exit(1)

    result = scan_path(target)
    print_ioc_report(result)
