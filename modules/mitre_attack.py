# modules/mitre_attack.py
"""
SentinelX - MITRE ATT&CK Mapping
Maps detected indicators to MITRE ATT&CK techniques.

Used to enrich findings with:
- Technique ID (e.g., T1059)
- Technique name
- Tactic (Persistence, Execution, etc.)
"""

import logging
from pathlib import Path

logger = logging.getLogger("SentinelX.mitre")

BASE_DIR = Path(__file__).parent.parent


# ============================================================
# ATT&CK Technique mapping
# keyword -> (technique_id, technique_name)
# ============================================================

ATTACK_MAP = {
    # ---- Persistence ----
    "persistence": ("T1547", "Boot or Logon Autostart Execution"),
    "startup_file": ("T1547.001", "Registry Run Keys / Startup Folder"),
    "cron": ("T1053.003", "Scheduled Task/Job: Cron"),
    "systemd": ("T1543.002", "Create or Modify System Process: Systemd Service"),
    "bashrc": ("T1546.004", "Event Triggered Execution: Unix Shell Config"),
    "profile_d": ("T1546.004", "Event Triggered Execution: Unix Shell Config"),
    "rc_local": ("T1037.004", "Boot or Logon Initialization Scripts: RC Scripts"),
    "launchagent": ("T1543.001", "Create or Modify System Process: Launch Agent"),
    "registry_run": ("T1547.001", "Registry Run Keys"),
    "scheduled_task": ("T1053.005", "Scheduled Task/Job: Scheduled Task"),

    # ---- Execution ----
    "reverse_shell": ("T1059", "Command and Scripting Interpreter"),
    "web_shell": ("T1505.003", "Server Software Component: Web Shell"),
    "powershell": ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "bash": ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    "python": ("T1059.006", "Command and Scripting Interpreter: Python"),
    "perl": ("T1059.006", "Command and Scripting Interpreter: Python"),
    "wmi": ("T1047", "Windows Management Instrumentation"),
    "exploit": ("T1203", "Exploitation for Client Execution"),

    # ---- Defense Evasion ----
    "obfuscated": ("T1027", "Obfuscated Files or Information"),
    "encoded": ("T1027", "Obfuscated Files or Information"),
    "base64": ("T1140", "Deobfuscate/Decode Files or Information"),
    "rootkit": ("T1014", "Rootkit"),
    "hidden_file": ("T1564.001", "Hide Artifacts: Hidden Files and Directories"),
    "masquerading": ("T1036", "Masquerading"),
    "timestomp": ("T1070.006", "Indicator Removal: Timestomp"),
    "log_clear": ("T1070.002", "Indicator Removal: Clear Linux or Mac System Logs"),

    # ---- Credential Access ----
    "keylogger": ("T1056.001", "Input Capture: Keylogging"),
    "credential": ("T1555", "Credentials from Password Stores"),
    "hash_dump": ("T1003", "OS Credential Dumping"),
    "clipboard": ("T1115", "Clipboard Data"),

    # ---- Discovery ----
    "network_scan": ("T1046", "Network Service Scanning"),
    "process_discovery": ("T1057", "Process Discovery"),
    "system_info": ("T1082", "System Information Discovery"),
    "file_discovery": ("T1083", "File and Directory Discovery"),

    # ---- Lateral Movement ----
    "smb": ("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    "ssh": ("T1021.004", "Remote Services: SSH"),
    "rdp": ("T1021.001", "Remote Services: Remote Desktop Protocol"),
    "winrm": ("T1021.006", "Remote Services: Windows Remote Management"),

    # ---- Collection ----
    "screen_capture": ("T1113", "Screen Capture"),
    "audio_capture": ("T1123", "Audio Capture"),
    "video_capture": ("T1125", "Video Capture"),
    "keylog": ("T1056.001", "Input Capture: Keylogging"),

    # ---- Command and Control ----
    "c2": ("T1071", "Application Layer Protocol"),
    "beacon": ("T1071", "Application Layer Protocol"),
    "dns_tunnel": ("T1071.004", "Application Layer Protocol: DNS"),
    "http_c2": ("T1071.001", "Application Layer Protocol: Web Protocols"),
    "custom_c2": ("T1095", "Non-Application Layer Protocol"),

    # ---- Exfiltration ----
    "exfil": ("T1041", "Exfiltration Over C2 Channel"),
    "dns_exfil": ("T1048.003", "Exfiltration Over Alternative Protocol: DNS"),

    # ---- Impact ----
    "ransomware": ("T1486", "Data Encrypted for Impact"),
    "encryption": ("T1486", "Data Encrypted for Impact"),
    "wiper": ("T1485", "Data Destruction"),
    "defacement": ("T1491", "Defacement"),

    # ---- Resource Hijacking ----
    "crypto_miner": ("T1496", "Resource Hijacking"),
    "miner": ("T1496", "Resource Hijacking"),
    "xmrig": ("T1496", "Resource Hijacking"),

    # ---- Android Specific ----
    "android_sms": ("T1582", "SMS Control"),
    "android_location": ("T1430", "Location Tracking"),
    "android_camera": ("T1512", "Video Capture"),
    "android_mic": ("T1429", "Audio Capture"),
    "android_contacts": ("T1636.003", "Protected User Data: Contact List"),
    "android_calendar": ("T1636.002", "Protected User Data: Calendar Entries"),
    "android_overlay": ("T1417.002", "Input Capture: GUI Input Capture"),
    "android_accessibility": ("T1453", "Abuse Accessibility Features"),
}


# ============================================================
# Mapping functions
# ============================================================

def map_indicator(indicator_type):
    """
    Map an indicator to ATT&CK technique.
    Returns (technique_id, technique_name) or (None, None).
    """
    if not indicator_type:
        return None, None

    key = indicator_type.lower().replace("-", "_").replace(" ", "_")

    # Exact match
    if key in ATTACK_MAP:
        return ATTACK_MAP[key]

    # Partial match
    for k, v in ATTACK_MAP.items():
        if k in key or key in k:
            return v

    return None, None


def enrich_finding(finding):
    """
    Add MITRE ATT&CK mapping to a finding.
    Modifies dict in place and returns it.
    """
    if not isinstance(finding, dict):
        return finding

    indicator = (
        finding.get("type") or
        finding.get("reason") or
        finding.get("category") or
        finding.get("rule") or
        ""
    )

    tid, technique = map_indicator(indicator)

    if tid:
        finding["mitre_id"] = tid
        finding["mitre_technique"] = technique

    return finding


def enrich_findings(findings):
    """Enrich a list of findings."""
    if not isinstance(findings, list):
        return findings
    return [enrich_finding(f) for f in findings]


def get_all_techniques():
    """Return all unique techniques."""
    seen = set()
    techniques = []

    for keyword, (tid, name) in ATTACK_MAP.items():
        if tid in seen:
            continue
        seen.add(tid)
        techniques.append({
            "id": tid,
            "name": name,
            "keyword": keyword,
        })

    return sorted(techniques, key=lambda x: x["id"])


def get_coverage_by_tactic():
    """Group techniques by tactic for reporting."""
    tactics = {
        "Persistence": [],
        "Execution": [],
        "Defense Evasion": [],
        "Credential Access": [],
        "Discovery": [],
        "Lateral Movement": [],
        "Collection": [],
        "Command and Control": [],
        "Exfiltration": [],
        "Impact": [],
        "Resource Hijacking": [],
        "Android": [],
    }

    for keyword, (tid, name) in ATTACK_MAP.items():
        # Simple heuristic by technique ID prefix
        if tid.startswith(("T1547", "T1053", "T1543", "T1546", "T1037", "T1505")):
            tactics["Persistence"].append((tid, name))
        elif tid.startswith(("T1059", "T1203", "T1047")):
            tactics["Execution"].append((tid, name))
        elif tid.startswith(("T1027", "T1140", "T1014", "T1564", "T1036", "T1070")):
            tactics["Defense Evasion"].append((tid, name))
        elif tid.startswith(("T1056", "T1555", "T1003", "T1115")):
            tactics["Credential Access"].append((tid, name))
        elif tid.startswith(("T1046", "T1057", "T1082", "T1083")):
            tactics["Discovery"].append((tid, name))
        elif tid.startswith(("T1021",)):
            tactics["Lateral Movement"].append((tid, name))
        elif tid.startswith(("T1113", "T1123", "T1125", "T1636")):
            tactics["Collection"].append((tid, name))
        elif tid.startswith(("T1071", "T1095")):
            tactics["Command and Control"].append((tid, name))
        elif tid.startswith(("T1041", "T1048")):
            tactics["Exfiltration"].append((tid, name))
        elif tid.startswith(("T1486", "T1485", "T1491")):
            tactics["Impact"].append((tid, name))
        elif tid.startswith(("T1496",)):
            tactics["Resource Hijacking"].append((tid, name))
        elif tid.startswith(("T1582", "T1430", "T1512", "T1429", "T1417", "T1453")):
            tactics["Android"].append((tid, name))

    # Remove empty
    return {k: v for k, v in tactics.items() if v}


def print_mitre_summary():
    """Print MITRE ATT&CK coverage summary."""
    print("\n" + "=" * 70)
    print("  MITRE ATT&CK Coverage - SentinelX")
    print("=" * 70)

    coverage = get_coverage_by_tactic()
    total = sum(len(v) for v in coverage.values())

    print(f"\n[*] Total mapped techniques: {total}")

    for tactic, techniques in coverage.items():
        print(f"\n[+] {tactic} ({len(techniques)})")
        for tid, name in techniques[:5]:
            print(f"    {tid}: {name[:55]}")
        if len(techniques) > 5:
            print(f"    ... and {len(techniques) - 5} more")

    print("\n" + "=" * 70 + "\n")


# ============================================================
# CLI Test
# ============================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print_mitre_summary()

    # Test mappings
    print("[*] Test mappings:")
    test_indicators = [
        "reverse_shell",
        "crypto_miner",
        "persistence",
        "web_shell",
        "android_sms",
        "keylogger",
        "ransomware",
        "unknown_indicator",
    ]

    for ind in test_indicators:
        tid, name = map_indicator(ind)
        if tid:
            print(f"  {ind:20} -> {tid}: {name}")
        else:
            print(f"  {ind:20} -> (not mapped)")

    # Test enrich
    print("\n[*] Test enrich:")
    finding = {"type": "reverse_shell", "path": "/tmp/x"}
    enriched = enrich_finding(finding)
    print(f"  {enriched}")

    print("\n[✓] mitre_attack works!")
