# modules/android_spyware.py
"""
SentinelX - Android Spyware Detection
Uses Termux:API to inspect SMS, call logs, contacts, and clipboard for
signs of surveillance or data exfiltration.
"""

import subprocess
import json
import logging
import platform
from datetime import datetime, timedelta

logger = logging.getLogger("SentinelX.android_spyware")


def _is_android():
    return "android" in platform.platform().lower()


def _run_api(cmd, timeout=15):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            return None, result.stderr.strip()
        output = result.stdout.strip()
        if not output:
            return None, "empty"
        try:
            return json.loads(output), None
        except json.JSONDecodeError:
            return output, None
    except FileNotFoundError:
        return None, f"{cmd[0]} not installed"
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except Exception as e:
        return None, str(e)


# Suspicious keywords in SMS/calls
SUSPICIOUS_SMS_KEYWORDS = [
    "verify", "verification", "code:", "otp",
    "password", "bank", "blocked", "suspended",
    "click here", "bit.ly", "tinyurl",
    "wire transfer", "bitcoin", "crypto wallet"
]

# Premium rate country codes (spyware often uses these)
PREMIUM_RATE_PREFIXES = ["+1900", "+1234", "+1800", "+880", "+234", "+92"]


def _analyze_sms(messages):
    """Look for spyware/phishing patterns in SMS."""
    alerts = []
    recent_cutoff = datetime.now() - timedelta(days=7)

    for msg in messages[:100]:
        try:
            body = (msg.get("body") or "").lower()
            sender = msg.get("number") or msg.get("address") or ""

            # Suspicious keywords
            for kw in SUSPICIOUS_SMS_KEYWORDS:
                if kw in body:
                    alerts.append({
                        "severity": "MEDIUM",
                        "type": "suspicious_sms",
                        "from": sender,
                        "detail": f"SMS with '{kw}': {body[:60]}..."
                    })
                    break

            # Premium rate numbers
            for prefix in PREMIUM_RATE_PREFIXES:
                if sender.startswith(prefix):
                    alerts.append({
                        "severity": "HIGH",
                        "type": "premium_rate_sms",
                        "from": sender,
                        "detail": f"SMS from premium number: {sender}"
                    })
                    break

        except Exception:
            continue

    return alerts


def _analyze_calls(calls):
    """Look for suspicious call patterns."""
    alerts = []

    for call in calls[:50]:
        try:
            number = call.get("number") or ""
            duration = call.get("duration", 0)
            call_type = call.get("type", "")

            # Premium rate
            for prefix in PREMIUM_RATE_PREFIXES:
                if number.startswith(prefix):
                    alerts.append({
                        "severity": "HIGH",
                        "type": "premium_call",
                        "number": number,
                        "detail": f"Call to premium number (duration: {duration}s)"
                    })
                    break

            # Very short calls (potential beacon)
            if call_type == "OUTGOING" and 0 < duration < 5:
                alerts.append({
                    "severity": "LOW",
                    "type": "short_call",
                    "number": number,
                    "detail": f"Very short outgoing call ({duration}s) — possible beacon"
                })

        except Exception:
            continue

    return alerts


def _analyze_clipboard(content):
    """Detect sensitive data in clipboard."""
    alerts = []
    if not content:
        return alerts

    content_lower = content.lower()

    # Crypto wallet addresses
    if any(x in content_lower for x in ["0x", "bc1", "1a1z", "3j98"]):
        alerts.append({
            "severity": "HIGH",
            "type": "crypto_address",
            "detail": "Clipboard contains possible crypto wallet address"
        })

    # Passwords
    if "password" in content_lower or "passwd" in content_lower:
        alerts.append({
            "severity": "HIGH",
            "type": "password_clipboard",
            "detail": "Clipboard contains 'password' keyword"
        })

    # Long base64-looking strings (potential exfil)
    if len(content) > 100 and all(c.isalnum() or c in "+/=" for c in content[:200]):
        alerts.append({
            "severity": "MEDIUM",
            "type": "base64_clipboard",
            "detail": "Clipboard contains long encoded string (possible exfil)"
        })

    return alerts


def run_android_spyware_check():
    """Main spyware detection scan."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "is_android": _is_android(),
        "sms_count": 0,
        "call_count": 0,
        "contact_count": 0,
        "clipboard": None,
        "alerts": [],
        "summary": {},
        "errors": []
    }

    if not _is_android():
        result["error"] = "Not on Android"
        return result

    # --- SMS ---
    sms, err = _run_api(["termux-sms-list", "-l", "200"], timeout=20)
    if sms and isinstance(sms, list):
        result["sms_count"] = len(sms)
        result["alerts"].extend(_analyze_sms(sms))
    elif err:
        result["errors"].append(f"SMS: {err}")

    # --- Call log ---
    calls, err = _run_api(["termux-call-log", "-l", "100"], timeout=20)
    if calls and isinstance(calls, list):
        result["call_count"] = len(calls)
        result["alerts"].extend(_analyze_calls(calls))
    elif err:
        result["errors"].append(f"Calls: {err}")

    # --- Contacts ---
    contacts, err = _run_api(["termux-contact-list"], timeout=20)
    if contacts and isinstance(contacts, list):
        result["contact_count"] = len(contacts)
    elif err:
        result["errors"].append(f"Contacts: {err}")

    # --- Clipboard ---
    clip, err = _run_api(["termux-clipboard-get"], timeout=5)
    if clip:
        result["clipboard"] = str(clip)[:200]
        result["alerts"].extend(_analyze_clipboard(str(clip)))

    result["summary"] = {
        "sms_scanned": result["sms_count"],
        "calls_scanned": result["call_count"],
        "contacts": result["contact_count"],
        "alerts": len(result["alerts"]),
        "high_severity": sum(1 for a in result["alerts"] if a["severity"] == "HIGH"),
    }

    return result


def print_android_spyware_report(result):
    print("\n" + "=" * 70)
    print("  Android Spyware Detection (Termux:API) - SentinelX")
    print("=" * 70)

    if result.get("error"):
        print(f"\n[!] Error: {result['error']}")
        return

    s = result.get("summary", {})
    print(f"\n[*] SMS scanned: {s.get('sms_scanned', 0)}")
    print(f"[*] Calls scanned: {s.get('calls_scanned', 0)}")
    print(f"[*] Contacts: {s.get('contacts', 0)}")
    print(f"[*] Total alerts: {s.get('alerts', 0)}")
    print(f"[*] High severity: {s.get('high_severity', 0)}")

    if result.get("clipboard"):
        print(f"\n[*] Clipboard preview: {result['clipboard'][:80]}")

    if result.get("alerts"):
        print(f"\n[!] Alerts:")
        for a in result["alerts"][:15]:
            marker = "🔴" if a["severity"] == "HIGH" else \
                     "🟡" if a["severity"] == "MEDIUM" else "🔵"
            print(f"    {marker} [{a['severity']}] {a['type']}")
            print(f"       {a.get('detail', '')}")

    if result.get("errors"):
        print(f"\n[!] Errors:")
        for e in result["errors"][:5]:
            print(f"    - {e}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    r = run_android_spyware_check()
    print_android_spyware_report(r)
