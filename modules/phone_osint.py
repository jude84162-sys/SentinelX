# modules/phone_osint.py
"""
SentinelX - Phone Number OSINT (Desktop + Android)
Analyzes international phone numbers for:
- Country, region, carrier, timezone, line type
- Risk scoring (premium rate, VoIP, high-risk countries)
- Reputation (public APIs — optional)

Requires: phonenumbers package  ->  pip install phonenumbers
"""

import re
import json
import logging
from datetime import datetime

logger = logging.getLogger("SentinelX.phone_osint")

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone, number_type
    HAS_PHONENUMBERS = True
except ImportError:
    HAS_PHONENUMBERS = False


# ============================================================
# Configuration
# ============================================================

PREMIUM_PREFIXES = [
    "+1900", "+1800",           # US premium / toll
    "+449", "+44871", "+44870", # UK premium
    "+881", "+882", "+883",     # Satellite
    "+870",                     # Inmarsat
]

HIGH_RISK_COUNTRIES = {
    "NG": "Nigeria — high fraud rate",
    "PK": "Pakistan — spoofing reports",
    "GH": "Ghana — advance-fee fraud",
    "CI": "Côte d'Ivoire — fraud rings",
    "RU": "Russia — spoofed caller ID",
    "IN": "India — tech support scams",
}

# Regions with incomplete carrier/type metadata (avoid false positives)
LIMITED_METADATA_REGIONS = {
    "SY", "IQ", "YE", "LY", "SD", "SO", "AF", "MM", "KP",
}

# Regions with fully reliable metadata
RELIABLE_METADATA_REGIONS = {
    "US", "CA", "GB", "DE", "FR", "IT", "ES", "NL", "BE",
    "CH", "AT", "SE", "NO", "DK", "FI", "JP", "KR", "AU",
    "NZ", "BR", "MX", "AR", "PL", "CZ", "PT", "IE",
}

# Human-readable region names (fallback map)
REGION_NAMES = {
    "US": "United States", "GB": "United Kingdom", "CA": "Canada",
    "AU": "Australia", "DE": "Germany", "FR": "France",
    "IT": "Italy", "ES": "Spain", "NL": "Netherlands",
    "BE": "Belgium", "CH": "Switzerland", "AT": "Austria",
    "SE": "Sweden", "NO": "Norway", "DK": "Denmark",
    "FI": "Finland", "JP": "Japan", "KR": "South Korea",
    "CN": "China", "IN": "India", "PK": "Pakistan",
    "RU": "Russia", "BR": "Brazil", "MX": "Mexico",
    "AR": "Argentina", "SY": "Syria", "SA": "Saudi Arabia",
    "AE": "UAE", "EG": "Egypt", "JO": "Jordan",
    "LB": "Lebanon", "IQ": "Iraq", "TR": "Turkey",
    "IR": "Iran", "IL": "Israel", "MA": "Morocco",
    "DZ": "Algeria", "TN": "Tunisia", "LY": "Libya",
}

# Number type labels
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
    "TOLL_FREE": 5,
    # UNKNOWN is NOT scored (incomplete metadata)
}


# ============================================================
# Parsing
# ============================================================

def _normalize(raw):
    """Parse and normalize a phone number string."""
    if not HAS_PHONENUMBERS:
        return None, "phonenumbers library not installed. Run: pip install phonenumbers"

    raw = raw.strip().replace(" ", "").replace("-", "")
    raw = raw.replace("(", "").replace(")", "")

    if not raw.startswith("+"):
        return None, "Number must start with + (e.g., +963912345678)"

    try:
        parsed = phonenumbers.parse(raw, None)
    except phonenumbers.NumberParseException as e:
        return None, f"Invalid number: {e}"

    if not phonenumbers.is_possible_number(parsed):
        return None, "Number is not possible for any region"

    return parsed, None


def _format_e164(parsed):
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)


def _format_international(parsed):
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)


def _format_national(parsed):
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)


# ============================================================
# Info extraction
# ============================================================

def _get_country_info(parsed):
    """Get country info with fallbacks."""
    try:
        region = phonenumbers.region_code_for_number(parsed) or "??"

        country = ""
        try:
            country = geocoder.country_name_for_number(parsed, "en") or ""
        except Exception:
            pass

        if not country or country == "Unknown":
            country = REGION_NAMES.get(region, region if region != "??" else "Unknown")

        description = ""
        try:
            description = geocoder.description_for_number(parsed, "en") or ""
        except Exception:
            pass

        return {
            "region_code": region,
            "country": country or "Unknown",
            "location": description or country or "",
        }
    except Exception as e:
        logger.debug(f"Country info failed: {e}")
        return {"region_code": "??", "country": "Unknown", "location": ""}


def _get_carrier(parsed):
    """Get carrier name."""
    try:
        name = carrier.name_for_number(parsed, "en") or "Unknown"
    except Exception:
        name = "Unknown"
    return {"name": name}


def _get_timezones(parsed):
    """Get timezones, filtering placeholders."""
    try:
        zones = list(timezone.time_zones_for_number(parsed))
        zones = [z for z in zones if z and z not in ("Etc/Unknown", "Etc/GMT")]
        if zones:
            return zones
    except Exception:
        pass
    return ["Unknown"]


def _get_number_type(parsed):
    """Get number type label."""
    try:
        t = number_type(parsed)
    except Exception:
        t = 27  # UNKNOWN
    label = TYPE_LABELS.get(t, "UNKNOWN")
    return {"code": t, "type": label}


# ============================================================
# Risk analysis
# ============================================================

def _analyze_risks(parsed, formatted_e164, country_info, number_type_info):
    """
    Compute risk score and reason list.
    Handles regions with incomplete metadata (e.g., Syria) gracefully.
    """
    risks = []
    score = 0

    region = country_info.get("region_code", "??")
    t = number_type_info.get("type", "UNKNOWN")

    # 1. Number type risk (skip UNKNOWN — incomplete data)
    type_already_scored = False
    if t in TYPE_RISK:
        score += TYPE_RISK[t]
        type_already_scored = True
        risks.append({
            "severity": "HIGH" if TYPE_RISK[t] >= 40 else "MEDIUM",
            "type": f"number_type_{t.lower()}",
            "detail": f"Number type is {t} (risk +{TYPE_RISK[t]})"
        })

    # 2. Premium rate prefixes
    #    Skip score accumulation if type already flagged it (PREMIUM_RATE)
    for prefix in PREMIUM_PREFIXES:
        if formatted_e164.startswith(prefix):
            if not type_already_scored:
                score += 50
            risks.append({
                "severity": "HIGH",
                "type": "premium_rate",
                "detail": f"Premium rate prefix: {prefix}"
            })
            break

    # 3. High-risk country
    if region in HIGH_RISK_COUNTRIES:
        score += 15
        risks.append({
            "severity": "MEDIUM",
            "type": "high_risk_country",
            "detail": HIGH_RISK_COUNTRIES[region]
        })

    # 4. VoIP detection (carrier name hints)
    try:
        carrier_name = (carrier.name_for_number(parsed, "en") or "").lower()
    except Exception:
        carrier_name = ""

    voip_keywords = [
        "google", "twilio", "vonage", "skype", "bandwidth",
        "plivo", "nexmo", "textnow", "textfree", "voip",
    ]
    for kw in voip_keywords:
        if kw in carrier_name:
            score += 20
            risks.append({
                "severity": "MEDIUM",
                "type": "voip_carrier",
                "detail": f"VoIP carrier: {carrier_name}"
            })
            break

    # 5. Unassigned number — only if region has complete metadata
    try:
        is_valid = phonenumbers.is_valid_number(parsed)
    except Exception:
        is_valid = True

    if not is_valid and region in RELIABLE_METADATA_REGIONS:
        score += 10
        risks.append({
            "severity": "LOW",
            "type": "unassigned",
            "detail": "Number format is valid but not currently assigned"
        })

    # Determine level
    if score >= 50:
        level = "CRITICAL"
    elif score >= 30:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    metadata_limited = (
        t == "UNKNOWN" and region in LIMITED_METADATA_REGIONS
    )

    return {
        "score": score,
        "level": level,
        "risks": risks,
        "metadata_limited": metadata_limited,
    }


# ============================================================
# Reputation (stub — optional APIs)
# ============================================================

def _reputation_stub(formatted_e164, region):
    """Placeholder for reputation checks."""
    region_lower = (region or "").lower()
    return {
        "checked": False,
        "reason": "External reputation APIs require API keys. "
                  "Set SENTINELX_TRUE_CALLER_KEY env var to enable.",
        "suggestions": [
            f'Search Google: "{formatted_e164}"',
            f"Search Truecaller: https://www.truecaller.com/search/"
            f"{region_lower}/{formatted_e164.lstrip('+')}",
            f"Search Have I Been Pwned: https://haveibeenpwned.com/",
            f"Search WhatsApp: https://wa.me/{formatted_e164.lstrip('+')}",
        ]
    }


# ============================================================
# Main entry
# ============================================================

def analyze_phone_number(raw_number):
    """Main entry point. Returns dict with full analysis."""
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
        "summary": {},
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
        result["number_type"],
    )
    result["reputation"] = _reputation_stub(
        result["formats"]["e164"],
        result["country"].get("region_code", ""),
    )

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


# ============================================================
# Report printer
# ============================================================

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

    # Formats
    print(f"\n[*] Formats:")
    for k, v in result["formats"].items():
        print(f"    {k:16} : {v}")

    # Country
    print(f"\n[*] Country info:")
    print(f"    Region:     {result['country'].get('region_code')}")
    print(f"    Country:    {result['country'].get('country')}")
    loc = result['country'].get('location', '')
    if loc:
        print(f"    Location:   {loc}")

    # Timezones — truncated
    tz = result.get("timezones", ["Unknown"])
    if len(tz) > 3:
        print(f"\n[*] Timezone(s): {', '.join(tz[:3])} (+{len(tz) - 3} more)")
    else:
        print(f"\n[*] Timezone(s): {', '.join(tz)}")

    # Risks
    risks = result["risk"].get("risks", [])
    if risks:
        print(f"\n[!] Risk Indicators:")
        for r in risks:
            marker = "🔴" if r["severity"] == "HIGH" else \
                     "🟡" if r["severity"] == "MEDIUM" else "🔵"
            print(f"    {marker} [{r['severity']}] {r['detail']}")
    else:
        print(f"\n[OK] No risk indicators detected")

    # Metadata note
    if result["risk"].get("metadata_limited"):
        print(f"\n[i] Note: Carrier/type data incomplete for this region.")
        print(f"    Risk analysis may be limited.")

    # Reputation
    rep = result.get("reputation", {})
    if not rep.get("checked"):
        print(f"\n[i] Reputation: not checked")
        print(f"    {rep.get('reason', '')}")
        print(f"    Try these manual lookups:")
        for sug in rep.get("suggestions", []):
            print(f"      - {sug}")

    print("\n" + "=" * 70 + "\n")


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m modules.phone_osint +963912345678")
        sys.exit(1)

    logging.basicConfig(level=logging.INFO)
    r = analyze_phone_number(sys.argv[1])
    print_phone_report(r)
