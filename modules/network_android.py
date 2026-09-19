# modules/network_android.py
"""
SentinelX - Android Network Triage via Termux:API
Uses termux-wifi-* commands to work around Android's /proc/net/tcp restrictions.
"""

import subprocess
import json
import logging
import platform
from datetime import datetime

logger = logging.getLogger("SentinelX.network_android")


def _is_android():
    return "android" in platform.platform().lower()


def _run_api(cmd, timeout=10):
    """Run a termux-api command and parse JSON output."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            return None, result.stderr.strip() or "command failed"

        output = result.stdout.strip()
        if not output:
            return None, "empty output"

        # Try to parse JSON (most termux-api commands return JSON)
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


def _has_termux_api():
    """Check if termux-api is installed and working."""
    result, error = _run_api(["termux-battery-status"], timeout=5)
    return result is not None and error is None


def get_wifi_info():
    """Get current WiFi connection info."""
    return _run_api(["termux-wifi-connectioninfo"])


def get_wifi_scan():
    """Scan nearby WiFi networks."""
    return _run_api(["termux-wifi-scaninfo"], timeout=20)


def get_telephony_info():
    """Get cellular network info."""
    return _run_api(["termux-telephony-deviceinfo"])


def get_ip_info():
    """Get public and local IP (via external lookup)."""
    import urllib.request
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as r:
            data = json.loads(r.read())
            return data, None
    except Exception as e:
        return None, str(e)


# Known safe DNS servers
SAFE_DNS = {
    "8.8.8.8", "8.8.4.4",        # Google
    "1.1.1.1", "1.0.0.1",        # Cloudflare
    "9.9.9.9", "149.112.112.112", # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
}

# Known suspicious WiFi patterns
SUSPICIOUS_WIFI_PATTERNS = [
    "free", "public", "open", "hack", "evil",
    "fake", "clone", "test", "spy"
]


def _analyze_wifi(wifi_info):
    """Analyze WiFi connection for suspicious indicators."""
    alerts = []

    if not wifi_info:
        return alerts

    # Check DNS servers
    dns_servers = wifi_info.get("dns_servers", "")
    if isinstance(dns_servers, str):
        dns_list = [d.strip() for d in dns_servers.split(",") if d.strip()]
    elif isinstance(dns_servers, list):
        dns_list = [str(d).strip() for d in dns_servers]
    else:
        dns_list = []

    for dns in dns_list:
        if dns and dns not in SAFE_DNS:
            alerts.append({
                "severity": "MEDIUM",
                "type": "custom_dns",
                "detail": f"Custom DNS detected: {dns} (could be MITM)"
            })

    # Check SSID
    ssid = (wifi_info.get("ssid") or "").strip('"').lower()
    for pattern in SUSPICIOUS_WIFI_PATTERNS:
        if pattern in ssid:
            alerts.append({
                "severity": "HIGH",
                "type": "suspicious_ssid",
                "detail": f"Suspicious WiFi name: {ssid}"
            })
            break

    # Check link speed
    link_speed = wifi_info.get("link_speed_mbps", 0)
    if isinstance(link_speed, (int, float)) and 0 < link_speed < 10:
        alerts.append({
            "severity": "LOW",
            "type": "slow_link",
            "detail": f"Very slow WiFi link: {link_speed} Mbps"
        })

    return alerts


def _analyze_wifi_scan(scan_results):
    """Analyze scanned networks for rogue APs."""
    alerts = []

    if not scan_results or not isinstance(scan_results, list):
        return alerts

    # Group by SSID to detect duplicates (evil twin)
    ssid_map = {}
    for ap in scan_results:
        ssid = (ap.get("SSID") or "").strip()
        if not ssid:
            continue
        bssid = (ap.get("BSSID") or "").strip()
        if ssid not in ssid_map:
            ssid_map[ssid] = []
        ssid_map[ssid].append(bssid)

    # Detect duplicate SSIDs with different BSSIDs (possible evil twin)
    for ssid, bssids in ssid_map.items():
        if len(bssids) > 1:
            alerts.append({
                "severity": "HIGH",
                "type": "evil_twin_suspect",
                "detail": f"SSID '{ssid}' broadcast by {len(bssids)} BSSIDs (possible evil twin)"
            })

    return alerts


def run_android_network_triage():
    """Main Android network triage."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "is_android": _is_android(),
        "termux_api_available": False,
        "wifi": None,
        "wifi_alerts": [],
        "wifi_scan": [],
        "wifi_scan_alerts": [],
        "telephony": None,
        "public_ip": None,
        "summary": {},
        "errors": []
    }

    if not _is_android():
        result["error"] = "Not on Android"
        return result

    if not _has_termux_api():
        result["error"] = "termux-api not available. Run: pkg install termux-api"

    result["termux_api_available"] = _has_termux_api()

    # WiFi info
    wifi_info, err = get_wifi_info()
    if wifi_info:
        result["wifi"] = wifi_info
        result["wifi_alerts"] = _analyze_wifi(wifi_info)
    elif err:
        result["errors"].append(f"WiFi info: {err}")

    # WiFi scan
    scan, err = get_wifi_scan()
    if scan:
        result["wifi_scan"] = scan
        result["wifi_scan_alerts"] = _analyze_wifi_scan(scan)
    elif err:
        result["errors"].append(f"WiFi scan: {err}")

    # Telephony
    telephony, err = get_telephony_info()
    if telephony:
        result["telephony"] = telephony

    # Public IP
    ip_info, err = get_ip_info()
    if ip_info:
        result["public_ip"] = ip_info.get("ip")

    # Summary
    result["summary"] = {
        "wifi_connected": wifi_info is not None,
        "wifi_alerts": len(result["wifi_alerts"]),
        "nearby_networks": len(result["wifi_scan"]),
        "evil_twin_alerts": len(result["wifi_scan_alerts"]),
        "total_alerts": len(result["wifi_alerts"]) + len(result["wifi_scan_alerts"])
    }

    return result


def print_android_network_report(result):
    """Print Android network report."""
    print("\n" + "=" * 70)
    print("  Android Network Triage (Termux:API) - SentinelX")
    print("=" * 70)

    if result.get("error"):
        print(f"\n[!] Error: {result['error']}")
        return

    if not result.get("termux_api_available"):
        print(f"\n[!] Termux:API not detected")
        return

    s = result.get("summary", {})
    print(f"\n[*] WiFi connected: {'✓' if s.get('wifi_connected') else '✗'}")
    print(f"[*] Nearby networks: {s.get('nearby_networks', 0)}")
    print(f"[*] WiFi alerts: {s.get('wifi_alerts', 0)}")
    print(f"[*] Evil twin alerts: {s.get('evil_twin_alerts', 0)}")

    # WiFi details
    wifi = result.get("wifi")
    if wifi:
        print(f"\n[*] Current WiFi:")
        print(f"    SSID:  {wifi.get('ssid', 'N/A')}")
        print(f"    BSSID: {wifi.get('bssid', 'N/A')}")
        print(f"    IP:    {wifi.get('ip_address', 'N/A')}")
        print(f"    Speed: {wifi.get('link_speed_mbps', 'N/A')} Mbps")
        print(f"    DNS:   {wifi.get('dns_servers', 'N/A')}")

    if result.get("public_ip"):
        print(f"\n[*] Public IP: {result['public_ip']}")

    # Telephony
    telephony = result.get("telephony")
    if telephony:
        print(f"\n[*] Telephony:")
        print(f"    Network:  {telephony.get('network_operator_name', 'N/A')}")
        print(f"    Country:  {telephony.get('network_country_iso', 'N/A')}")
        print(f"    SIM state: {telephony.get('sim_state', 'N/A')}")

    # Alerts
    all_alerts = result.get("wifi_alerts", []) + result.get("wifi_scan_alerts", [])
    if all_alerts:
        print(f"\n[!] Alerts:")
        for a in all_alerts:
            marker = "🔴" if a["severity"] == "HIGH" else \
                     "🟡" if a["severity"] == "MEDIUM" else "🔵"
            print(f"    {marker} [{a['severity']}] {a['detail']}")

    if result.get("errors"):
        print(f"\n[!] Errors:")
        for e in result["errors"][:5]:
            print(f"    - {e}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    r = run_android_network_triage()
    print_android_network_report(r)
