#!/usr/bin/env python3
"""
SentinelX - Modular Enterprise Blue Team Suite
Cross-platform: Termux, WSL, Kali, Linux, macOS.

Main entry point.
"""

import json
import argparse
import logging
from datetime import datetime
from pathlib import Path

# Environment detection
from modules.env_detect import get_environment, get_env_label, print_env_info

# Core modules
from modules.process import run_process_triage, print_process_report
from modules.network import run_network_analysis, print_network_report
from modules.files import run_file_triage, print_file_report
from modules.persistence import run_persistence_check, print_persistence_report
from modules.resources import run_resource_check, print_resource_report

# Android modules
from modules.network_android import run_android_network_triage, print_android_network_report
from modules.android_osint import run_android_osint, print_android_osint_report
from modules.android_spyware import run_android_spyware_check, print_android_spyware_report

# Notifications
from modules.notify import send_summary_notification as android_summary
from modules.desktop_notify import send_summary_notification as desktop_summary
from modules.desktop_notify import notify as desktop_notify

# Desktop OSINT
from modules.phone_osint import analyze_phone_number, print_phone_report

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SentinelX")

# Paths
BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


def print_banner(env):
    label = get_env_label(env)
    print("=" * 75)
    print("       SentinelX - Modular Enterprise Blue Team Suite")
    print(f"       Environment: {label}")
    print("=" * 75)


def save_report(report_data, filename="full_triage_report.json"):
    output_path = OUTPUT_DIR / filename
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"[+] Report saved to {output_path.relative_to(BASE_DIR)}")
        return True
    except Exception as e:
        logger.error(f"[-] Failed to save report: {e}")
        return False


def _send_notification(env, report_data):
    """Send native notification — Android or Desktop."""
    if env["is_android"] and env["has_termux_api"]:
        try:
            android_summary(report_data)
        except Exception as e:
            logger.debug(f"Android notification failed: {e}")
    elif env["has_desktop_notify"]:
        try:
            desktop_summary(report_data)
        except Exception as e:
            logger.debug(f"Desktop notification failed: {e}")


def run_triage_all(output_file="full_triage_report.json"):
    env = get_environment()

    report_data = {
        "timestamp": datetime.now().isoformat(),
        "version": "1.1.0",
        "mode": "triage-all",
        "environment": {
            "label": get_env_label(env),
            "platform": env["platform"],
            "is_android": env["is_android"],
            "is_termux": env["is_termux"],
            "is_wsl": env["is_wsl"],
            "is_kali": env["is_kali"],
            "is_root": env["is_root"],
            "has_termux_api": env["has_termux_api"],
            "has_desktop_notify": env["has_desktop_notify"],
            "has_phonenumbers": env["has_phonenumbers"],
            "capabilities": env["capabilities"],
        }
    }

    # 1. Process triage
    if env["capabilities"]["process_triage"]:
        logger.info("[*] Running Deep Process Triage...")
        report_data["processes"] = run_process_triage()
        print_process_report(report_data["processes"])
    else:
        logger.warning("[!] Process triage unavailable")
        report_data["processes"] = {"error": "unavailable"}

    # 2. Resources (NEW)
    logger.info("[*] Checking System Resources...")
    report_data["resources"] = run_resource_check()
    print_resource_report(report_data["resources"])

    # 3. Network (psutil)
    logger.info("[*] Analyzing Active Network Connections...")
    report_data["network"] = run_network_analysis()
    print_network_report(report_data["network"])

    # 4. File triage
    logger.info("[*] Scanning File System for Suspicious Files...")
    report_data["files"] = run_file_triage()
    print_file_report(report_data["files"])

    # 5. Persistence
    logger.info("[*] Checking Persistence Mechanisms...")
    report_data["persistence"] = run_persistence_check()
    print_persistence_report(report_data["persistence"])

    # 6. Android-only modules
    if env["is_android"]:
        logger.info("[*] Running Android OSINT (Apps & Permissions)...")
        report_data["android_osint"] = run_android_osint()
        print_android_osint_report(report_data["android_osint"])

        if env["has_termux_api"]:
            logger.info("[*] Running Android Network Triage (Termux:API)...")
            report_data["android_network"] = run_android_network_triage()
            print_android_network_report(report_data["android_network"])

            logger.info("[*] Running Android Spyware Detection...")
            report_data["android_spyware"] = run_android_spyware_check()
            print_android_spyware_report(report_data["android_spyware"])
        else:
            logger.info("[i] Skipping Termux:API modules (not available)")

    # Save report
    save_report(report_data, output_file)

    # Send notification
    _send_notification(env, report_data)

    return report_data


def main():
    parser = argparse.ArgumentParser(
        description="SentinelX - Blue Team Security Suite (Termux/WSL/Kali/Linux/macOS)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--triage-all", action="store_true", help="Run all modules")
    parser.add_argument("--process", action="store_true", help="Process analysis only")
    parser.add_argument("--resources", action="store_true", help="Resource monitor (CPU/RAM/battery/thermal)")
    parser.add_argument("--network", action="store_true", help="Network analysis only")
    parser.add_argument("--files", action="store_true", help="File triage only")
    parser.add_argument("--persistence", action="store_true", help="Persistence check only")
    parser.add_argument("--android", action="store_true", help="Android OSINT only")
    parser.add_argument("--android-network", action="store_true", help="Android network (Termux:API) only")
    parser.add_argument("--spyware", action="store_true", help="Android spyware detection only")
    parser.add_argument("--phone", type=str, default=None,
                        help="Analyze a phone number in E.164 format (e.g. +963912345678)")
    parser.add_argument("--notify-test", action="store_true", help="Test notification system")
    parser.add_argument("--env", action="store_true", help="Show environment info")
    parser.add_argument("--output", type=str, default="full_triage_report.json",
                        help="Output report filename")
    parser.add_argument("--version", action="version", version="SentinelX 1.1.0")

    args = parser.parse_args()

    env = get_environment()
    print_banner(env)

    # --- Special commands ---
    if args.env:
        print_env_info(env)
        return

    if args.notify_test:
        if env["is_android"] and env["has_termux_api"]:
            from modules.notify import notify as and_notify
            and_notify("SentinelX Test", "Android notifications OK")
            print("[+] Android notification sent")
        elif env["has_desktop_notify"]:
            desktop_notify("SentinelX Test", "Desktop notifications OK")
            print("[+] Desktop notification sent")
        else:
            print("[!] No notification system available")
        return

    # --- Phone OSINT ---
    if args.phone:
        result = analyze_phone_number(args.phone)
        print_phone_report(result)
        save_report({"phone_osint": result}, args.output)

        if result.get("valid") and result["summary"]["risk_level"] in ("HIGH", "CRITICAL"):
            if env["has_desktop_notify"]:
                desktop_notify(
                    "Phone Risk Detected",
                    f"{result['summary']['e164']} - {result['summary']['risk_level']} risk",
                    urgency="normal"
                )
        return

    # --- Module-specific runs ---
    if args.triage_all:
        run_triage_all(args.output)
    elif args.process:
        result = run_process_triage()
        print_process_report(result)
        save_report({"processes": result}, args.output)
    elif args.resources:
        result = run_resource_check()
        print_resource_report(result)
        save_report({"resources": result}, args.output)
    elif args.network:
        result = run_network_analysis()
        print_network_report(result)
        save_report({"network": result}, args.output)
    elif args.files:
        result = run_file_triage()
        print_file_report(result)
        save_report({"files": result}, args.output)
    elif args.persistence:
        result = run_persistence_check()
        print_persistence_report(result)
        save_report({"persistence": result}, args.output)
    elif args.android:
        result = run_android_osint()
        print_android_osint_report(result)
        save_report({"android_osint": result}, args.output)
    elif args.android_network:
        result = run_android_network_triage()
        print_android_network_report(result)
        save_report({"android_network": result}, args.output)
    elif args.spyware:
        result = run_android_spyware_check()
        print_android_spyware_report(result)
        save_report({"android_spyware": result}, args.output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
