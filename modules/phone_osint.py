# modules/phone_osint.py
"""
SentinelX - Phone Number OSINT (Desktop)
Analyzes international phone numbers for:
- Country, region, carrier, timezone, line type
- Reputation (spam/fraud lists, public leaks)
- Pattern anomalies (premium rate, disposable, VoIP)
Requires: phonenumbers package  ->  pip install phonenumbers
"""

import re
import json
import logging
from datetime import datetime

logger = logging.getLogger("SentinelX.phone_osint")

# Optional import — graceful if missing
try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone, number_type, PhoneNumberType
    HAS_PHONENUMBERS = True
except ImportError:
    HAS_PHONENUMBERS = False


# Known premium / fraud prefixes
PREMIUM_PREFIXES = [
    "+1900", "+1800",  # US premium
    "+449", "+44871", "+44870",  # UK premium
    "+881", "+882", "+883",  # Satellite
    "+870",  # Inmarsat
]

# Known fraud-prone country codes (high abuse rate)
HIGH_RISK_COUNTRIES = {
    "NG": "Nigeria — high fraud rate",
    "PK": "Pakistan — spoofing reports",
    "GH": "Ghana — advance-fee fraud",
    "CI": "Côte d'Ivoire — fraud rings",
    "RU": "Russia — spoofed caller ID",
    "IN": "India — tech support scams",
}

# Number type classifications
TYPE_LABELS = {
    0: "FIXED_LINE",
    1: "MOBILE",
    2: "FIXED_LINE_OR_MOBILE",
    3: "TOLL_FREE",
    4: "PREMIUM_RATE",
    5: "SHARED_COST",
    6: "VOIP",
    7: "PERSONAL_NUMBER",
    8: "PAGER",
    9: "UAN",
    10: "VOICEMAIL",
    27: "UNKNOWN",
}

# Risk scores per type
TYPE_RISK = {
    "PREMIUM_RATE": 40,
    "VOIP": 25,
    "PERSONAL_NUMBER": 20,
    "PAGER": 15,
    "UNKNOWN": 10,
    "TOLL_FREE": 5,
}


def _normalize(raw):
    """Try to parse and normalize a phone number string."""
    if not HAS_PHONENUMBERS:
        return None, "phonenumbers library not installed. Run: pip install phonenumbers"

    raw = raw.strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")

    # Must start with +
    if not raw.startswith("+"):
        return None, "Number must start with + (international format), e.g. +963912345678"

    try:
        parsed = phonenumbers.parse(raw, None)
    except phonenumbers.NumberParseException as e:
        return None, f"Invalid number: {e}"

    if not phonenumbers.is_valid_number(parsed):
        # Still return — could be a valid-format-but-unassigned number
        if not phonenumbers.is_possible_number(parsed):
            return None, "Number is not even possible for the region"

    return parsed, None


def _format_e164(parsed):
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)


def _format_international(parsed):
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)


def _format_national(parsed):
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)


def _get_country_info(parsed):
    region = phonenumbers.region_code_for_number(parsed) or "??"
    country = geocoder.country_name_for_number(parsed, "en") or "Unknown"
    description = geocoder.description_for_number(parsed, "en") or ""
    return {
        "region_code": region,
        "country": country,
        "location": description
    }


def _get_carrier(parsed):
    name = carrier.name_for_number(parsed, "en") or "Unknown"
    return {"name": name, "is_voip": False}


def _get_timezones(parsed):
    return list(timezone.time_zones_for_number(parsed)) or ["Unknown"]


def _get_number_type(parsed):
    t = number_type(parsed)
    label = TYPE_LABELS.get(t, "UNKNOWN")
    return {"code": t, "type": label}


def _analyze_risks(parsed, formatted_e164, country_info, number_type_info):
    """Compute risk score and reason list."""
    risks = []
    score = 0

    # 1. Number type risks
    t = number_type_info["type"]
    if t in TYPE_RISK:
        score += TYPE_RISK[t]
        risks.append({
            "severity": "HIGH" if TYPE_RISK[t] >= 40 else "MEDIUM",
            "type": f"number_type_{t.lower()}",
            "detail": f"Number type is {t} (risk +{TYPE_RISK[t]})"
        })

    # 2. Premium rate prefixes
    for prefix in PREMIUM_PREFIXES:
        if formatted_e164.startswith(prefix):
            score += 50
            risks.append({
                "severity": "HIGH",
                "type": "premium_rate",
                "detail": f"Premium rate prefix: {prefix}"
            })
            break

    # 3. High-risk country
    region = country_info.get("region_code")
    if region in HIGH_RISK_COUNTRIES:
        score += 15
        risks.append({
            "severity": "MEDIUM",
            "type": "high_risk_country",
            "detail": HIGH_RISK_COUNTRIES[region]
        })

    # 4. VoIP detection (carrier name hints)
    carrier_name = (carrier.name_for_number(parsed, "en") or "").lower()
    voip_keywords = ["google", "twilio", "vonage", "skype", "bandwidth",
                     "plivo", "nexmo", "voice", "voip", "textnow", "textfree"]
    for kw in voip_keywords:
        if kw in carrier_name:
            score += 20
            risks.append({
                "severity": "MEDIUM",
                "type": "voip_carrier",
                "detail": f"VoIP carrier detected: {carrier.name_for_number(parsed, 'en')}"
            })
            break

    # 5. Unassigned but valid format
    if not phonenumbers.is_valid_number(parsed):
        score += 10
        risks.append({
            "severity": "LOW",
            "type": "unassigned",
            "detail": "Number format is valid but not currently assigned"
        })

    if score >= 50:
        level = "CRITICAL"
    elif score >= 30:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "risks": risks
    }


def _reputation_stub(formatted_e164):
    """
    Placeholder for reputation checks.
    Real integrations would call:
      - Truecaller API (requires key)
      - numlookupapi.com (requires key)
      - Twilio Lookup (requires key)
      - Have I Been Pwned (phone leaks)
    Without keys, we return 'unchecked'.
    """
    return {
        "checked": False,
        "reason": "External reputation APIs require API keys (Truecaller, Twilio, HIBP). "
                  "Set SENTINELX_TRUE_CALLER_KEY env var to enable.",
        "suggestions": [
            f"Search Google: \"{formatted_e164}\"",
            f"Search Truecaller: https://www.truecaller.com/search/{{region}}/{formatted_e164.lstrip('+')}",
            f"Search Have I Been Pwned: https://haveibeenpwned.com/",
            f"Search WhatsApp: https://wa.me/{formatted_e164.lstrip('+')}",
        ]
    }


def analyze_phone_number(raw_number):
    """
    Main entry point. Returns a dict with full analysis.
    """
    result = {
        "timestamp": datetime.now().isoformat(),
        "input": raw_number,
        "valid": False,
        "error": None,
        "formats": {},
        "country": {},
        "carrier": {},
        "timezones": [],
        "number_type": {},
        "risk": {},
        "reputation": {},
        "summary": {}
    }

    parsed, error = _normalize(raw_number)
    if parsed is None:
        result["error"] = error
        return result

    result["valid"] = True
    result["formats"] = {
        "e164": _format_e164(parsed),
        "international": _format_international(parsed),
        "national": _format_national(parsed),
        "country_code": parsed.country_code,
        "national_number": parsed.national_number,
    }
    result["country"] = _get_country_info(parsed)
    result["carrier"] = _get_carrier(parsed)
    result["timezones"] = _get_timezones(parsed)
    result["number_type"] = _get_number_type(parsed)
    result["risk"] = _analyze_risks(
        parsed,
        result["formats"]["e164"],
        result["country"],
        result["number_type"]
    )
    result["reputation"] = _reputation_stub(result["formats"]["e164"])

    result["summary"] = {
        "e164": result["formats"]["e164"],
        "country": result["country"].get("country", "?"),
        "carrier": result["carrier"].get("name", "?"),
        "type": result["number_type"].get("type", "?"),
        "risk_level": result["risk"].get("level", "?"),
        "risk_score": result["risk"].get("score", 0),
        "risk_count": len(result["risk"].get("risks", [])),
    }

    return result


def print_phone_report(result):
    print("\n" + "=" * 70)
    print("  Phone Number OSINT Report - SentinelX")
    print("=" * 70)

    if not result.get("valid"):
        print(f"\n[!] Invalid number: {result.get('error', 'unknown error')}")
        return

    s = result["summary"]
    print(f"\n[*] Input:      {result['input']}")
    print(f"[*] E.164:      {s['e164']}")
    print(f"[*] Country:    {s['country']}")
    print(f"[*] Carrier:    {s['carrier']}")
    print(f"[*] Type:       {s['type']}")
    print(f"[*] Risk:       {s['risk_level']} (score {s['risk_score']})")

    print(f"\n[*] Formats:")
    for k, v in result["formats"].items():
        print(f"    {k:16} : {v}")

    print(f"\n[*] Country info:")
    print(f"    Region:     {result['country'].get('region_code')}")
    print(f"    Country:    {result['country'].get('country')}")
    print(f"    Location:   {result['country'].get('location', '(not available)')}")

    print(f"\n[*] Timezone(s): {', '.join(result['timezones'])}")

    risks = result["risk"].get("risks", [])
    if risks:
        print(f"\n[!] Risk Indicators:")
        for r in risks:
            marker = "🔴" if r["severity"] == "HIGH" else \
                     "🟡" if r["severity"] == "MEDIUM" else "🔵"
            print(f"    {marker} [{r['severity']}] {r['detail']}")
    else:
        print(f"\n[✓] No risk indicators detected")

    rep = result.get("reputation", {})
    if not rep.get("checked"):
        print(f"\n[i] Reputation: not checked")
        print(f"    {rep.get('reason', '')}")
        print(f"    Try these manual lookups:")
        for sug in rep.get("suggestions", []):
            print(f"      • {sug}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m modules.phone_osint +963912345678")
        sys.exit(1)
    r = analyze_phone_number(sys.argv[1])
    print_phone_report(r)
