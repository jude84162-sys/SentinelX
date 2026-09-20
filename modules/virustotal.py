# modules/virustotal.py
"""
SentinelX - VirusTotal Integration
Checks file hashes against 70+ antivirus engines.

Requires FREE API key: https://www.virustotal.com/gui/my-apikey

Set env: export VT_API_KEY="your_key_here"

Free tier limits:
- 4 requests per minute
- 500 requests per day
- 15.5K requests per month
"""

import os
import json
import time
import hashlib
import logging
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger("SentinelX.virustotal")

BASE_DIR = Path(__file__).parent.parent
CACHE_DIR = BASE_DIR / "state"
CACHE_DIR.mkdir(exist_ok=True)
VT_CACHE = CACHE_DIR / "virustotal_cache.json"
CACHE_TTL_HOURS = 24

API_BASE = "https://www.virustotal.com/api/v3"


# ============================================================
# API Key management
# ============================================================

def get_api_key():
    """Get VirusTotal API key from environment."""
    key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
    if key:
        key = key.strip()
    return key


def is_api_key_valid(key=None):
    """Check if API key looks valid (length check)."""
    key = key or get_api_key()
    if not key:
        return False
    # VirusTotal API keys are typically 64 chars
    return len(key) >= 32


# ============================================================
# Cache management
# ============================================================

def _load_cache():
    if VT_CACHE.exists():
        try:
            return json.load(open(VT_CACHE))
        except Exception:
            pass
    return {}


def _save_cache(cache):
    try:
        # Keep max 1000 entries
        if len(cache) > 1000:
            items = sorted(
                cache.items(),
                key=lambda x: x[1].get("_cached_at", ""),
                reverse=True
            )[:1000]
            cache = dict(items)

        with open(VT_CACHE, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass


def _get_cached(sha256):
    """Get cached result if fresh."""
    cache = _load_cache()
    if sha256 in cache:
        cached = cache[sha256]
        try:
            cached_at = datetime.fromisoformat(
                cached.get("_cached_at", "1970-01-01")
            )
            if datetime.now() - cached_at < timedelta(hours=CACHE_TTL_HOURS):
                return cached
        except Exception:
            pass
    return None


def _set_cached(sha256, result):
    cache = _load_cache()
    result["_cached_at"] = datetime.now().isoformat()
    cache[sha256] = result
    _save_cache(cache)


# ============================================================
# VirusTotal API
# ============================================================

def check_hash(sha256, api_key=None):
    """
    Check SHA-256 hash against VirusTotal.
    Returns dict with detection stats.
    """
    if not sha256:
        return {"error": "no_hash"}

    # Get API key
    key = api_key or get_api_key()

    # Check cache first (works without API key)
    cached = _get_cached(sha256.lower())
    if cached:
        logger.debug(f"Using cached VT result for {sha256[:16]}...")
        return cached

    # Need API key for new checks
    if not key:
        return {"error": "no_api_key", "sha256": sha256}

    if not is_api_key_valid(key):
        return {"error": "invalid_api_key", "sha256": sha256}

    # Make API request
    url = f"{API_BASE}/files/{sha256.lower()}"
    headers = {"x-apikey": key, "Accept": "application/json"}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            response = json.loads(r.read())

        attrs = response.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        result = {
            "sha256": sha256.lower(),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total": sum(stats.values()),
            "scan_date": attrs.get("last_analysis_date"),
            "meaningful_name": attrs.get("meaningful_name", ""),
            "type": attrs.get("type_description", ""),
            "reputation": attrs.get("reputation", 0),
        }

        _set_cached(sha256.lower(), result)
        return result

    except urllib.error.HTTPError as e:
        if e.code == 404:
            result = {
                "sha256": sha256.lower(),
                "not_found": True,
                "message": "Hash not in VirusTotal database",
            }
            _set_cached(sha256.lower(), result)
            return result

        if e.code == 429:
            logger.warning("VirusTotal rate limit reached (4 req/min free)")
            return {"error": "rate_limit", "sha256": sha256}

        if e.code == 401:
            return {"error": "invalid_api_key", "sha256": sha256}

        if e.code == 403:
            return {"error": "forbidden", "sha256": sha256}

        return {"error": f"http_{e.code}", "sha256": sha256}

    except urllib.error.URLError as e:
        return {"error": f"network: {e.reason}", "sha256": sha256}

    except Exception as e:
        logger.debug(f"VT error: {e}")
        return {"error": str(e), "sha256": sha256}


def check_file(filepath, api_key=None):
    """
    Check a file against VirusTotal using its hash.
    Returns dict with detection stats.
    """
    if not os.path.isfile(filepath):
        return {"error": "file_not_found", "path": filepath}

    # Calculate hash
    try:
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()
    except (OSError, PermissionError) as e:
        return {"error": f"hash_failed: {e}", "path": filepath}

    result = check_hash(file_hash, api_key)
    if result:
        result["path"] = filepath
    return result


def check_hashes_batch(hashes, api_key=None, delay=16):
    """
    Check multiple hashes with rate limiting.
    Free tier: 4 requests/min = 15s delay between requests.
    """
    results = []

    for i, h in enumerate(hashes):
        logger.info(f"Checking {i+1}/{len(hashes)}: {h[:16]}...")
        r = check_hash(h, api_key)
        if r:
            results.append(r)

        # Rate limit (except last)
        if i < len(hashes) - 1:
            time.sleep(delay)

    return results


# ============================================================
# Report
# ============================================================

def print_vt_report(result):
    print("\n" + "=" * 70)
    print("  VirusTotal Report - SentinelX")
    print("=" * 70)

    if not result:
        print(f"\n[!] No data")
        return

    # Error handling
    if result.get("error"):
        error = result["error"]

        if error == "no_api_key":
            print(f"\n[!] No VirusTotal API key found.")
            print(f"    Get free key: https://www.virustotal.com/gui/my-apikey")
            print(f"    Then: export VT_API_KEY='your_key_here'")
            return

        if error == "invalid_api_key":
            print(f"\n[!] Invalid API key.")
            print(f"    Verify your key at: https://www.virustotal.com/gui/my-apikey")
            return

        if error == "rate_limit":
            print(f"\n[!] Rate limit reached (4 requests/minute on free tier)")
            print(f"    Wait 1 minute and try again")
            return

        if error == "file_not_found":
            print(f"\n[!] File not found: {result.get('path', '?')}")
            return

        if error.startswith("network"):
            print(f"\n[!] Network error: {error}")
            print(f"    Check your internet connection")
            return

        print(f"\n[!] Error: {error}")
        return

    # Not found
    if result.get("not_found"):
        print(f"\n[*] SHA-256: {result.get('sha256', '?')}")
        print(f"[✓] Hash not in VirusTotal database (likely benign or very new)")
        return

    # Success
    sha = result.get("sha256", "?")
    print(f"\n[*] File: {result.get('path', 'N/A')}")
    print(f"[*] SHA-256: {sha[:32]}...{sha[-16:]}" if len(sha) > 48 else f"[*] SHA-256: {sha}")

    mal = result.get("malicious", 0)
    sus = result.get("suspicious", 0)
    total = result.get("total", 0)

    if total == 0:
        print(f"[*] Detection: no data")
        return

    print(f"[*] Detection: {mal}/{total} engines")

    # Verdict
    if mal == 0 and sus == 0:
        print(f"\n[✓] CLEAN — no engines detected threats")
    elif mal >= 20:
        print(f"\n[🔴] CRITICAL — {mal} engines flagged as malware!")
    elif mal >= 5:
        print(f"\n[🔴] HIGH RISK — {mal} engines flagged as malware")
    elif mal >= 1:
        print(f"\n[⚠️] WARNING — {mal} engines flagged as malware")
    elif sus >= 1:
        print(f"\n[🟡] SUSPICIOUS — {sus} engines flagged")

    # Details
    if result.get("meaningful_name"):
        print(f"\n[*] Name: {result['meaningful_name']}")
    if result.get("type"):
        print(f"[*] Type: {result['type']}")
    if result.get("reputation") is not None:
        rep = result["reputation"]
        rep_marker = "🔴" if rep < -50 else "🟡" if rep < 0 else "🟢"
        print(f"[*] Reputation: {rep_marker} {rep}")

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
        print("Usage: python -m modules.virustotal <file_or_hash>")
        print("       python -m modules.virustotal ~/eicar_test.txt")
        print("       python -m modules.virustotal 275a021bbfb6489e...")
        print()
        print("Requires: VT_API_KEY environment variable")
        print("Get free key: https://www.virustotal.com/gui/my-apikey")
        sys.exit(1)

    target = sys.argv[1]

    # Check if it's a file or hash
    if os.path.isfile(target):
        result = check_file(target)
    elif len(target) == 64 and all(c in "0123456789abcdefABCDEF" for c in target):
        # It's a SHA-256 hash
        result = check_hash(target.lower())
    else:
        # Try as file
        expanded = os.path.expanduser(target)
        if os.path.isfile(expanded):
            result = check_file(expanded)
        else:
            print(f"[!] Not a file or valid SHA-256 hash: {target}")
            sys.exit(1)

    print_vt_report(result)
