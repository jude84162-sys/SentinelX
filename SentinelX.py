#!/usr/bin/env python3
"""
SentinelX - Modular Enterprise Blue Team Suite
Cross-platform: Termux, WSL, Kali, Linux, macOS.
"""

import sys
import json
import argparse
import logging
from datetime import datetime
from pathlib import Path

from modules.env_detect import get_environment, get_env_label, print_env_info
from modules.process import run_process_triage, print_process_report
from modules.network import run_network_analysis, print_network_report
from modules.files import run_file_triage, print_file_report
from modules.persistence import run_persistence_check, print_persistence_report
from modules.android_osint import run_android_osint, print_android_osint_report
from modules.html_report import generate_html_report

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SentinelX")

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
        logger.info(f"[✓] Report saved to {output_path.relative_to(BASE_DIR)}")
        return True
    except Exception as e:
        logger.error(f"[✗] Failed to save report: {e}")
        return False


def run_triage_all(output_file="full_triage_report.json", html_filename="report.html"):
    env = get_environment()

    report_data = {
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "mode": "triage-all",
        "environment": {
            "label": get_env_label(env),
            "platform": env["platform"],
            "is_android": env["is_android"],
            "is_wsl": env["is_wsl"],
            "is_kali": env["is_kali"],
            "is_root": env["is_root"],
            "capabilities": env["capabilities"]
        }
    }

    # 1. Process
    if env["capabilities"]["process_triage"]:
        logger.info("[*] Running Deep Process Triage...")
        report_data["processes"] = run_process_triage()
        print_process_report(report_data["processes"])
    else:
        logger.warning("[!] Process triage unavailable")
        report_data["processes"] = {"error": "unavailable"}

    # 2. Network
    logger.info("[*] Analyzing Active Network Connections...")
    report_data["network"] = run_network_analysis()
    print_network_report(report_data["network"])

    # 3. Files
    logger.info("[*] Scanning File System for Suspicious Files...")
    report_data["files"] = run_file_triage()
    print_file_report(report_data["files"])

    # 4. Persistence
    logger.info("[*] Checking Persistence Mechanisms...")
    report_data["persistence"] = run_persistence_check()
    print_persistence_report(report_data["persistence"])

    # 5. Android OSINT — only on Android
    if env["is_android"]:
        logger.info("[*] Running Android OSINT (Apps & Permissions)...")
        report_data["android_osint"] = run_android_osint()
        print_android_osint_report(report_data["android_osint"])
    else:
        logger.info("[i] Skipping Android OSINT (not on Android)")
        report_data["android_osint"] = {"skipped": True, "reason": "not on Android"}

    # Save JSON report
    save_report(report_data, output_file)
    
    # Generate HTML Dashboard report
    logger.info("[*] Generating HTML Dashboard Report...")
    generate_html_report(report_data, html_filename)

    return report_data


def main():
    parser = argparse.ArgumentParser(
        description="SentinelX - Blue Team Security Suite (Termux/WSL/Kali/Linux)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--triage-all", action="store_true", help="Run all modules & generate reports")
    parser.add_argument("--process", action="store_true", help="Process analysis only")
    parser.add_argument("--network", action="store_true", help="Network analysis only")
    parser.add_argument("--files", action="store_true", help="File triage only")
    parser.add_argument("--persistence", action="store_true", help="Persistence check only")
    parser.add_argument("--android", action="store_true", help="Android OSINT only")
    parser.add_argument("--env", action="store_true", help="Show environment info")
    parser.add_argument("--output", type=str, default="full_triage_report.json")
    parser.add_argument("--html-output", type=str, default="report.html")
    parser.add_argument("--version", action="version", version="SentinelX 1.0.0")

    args = parser.parse_args()

    env = get_environment()
    print_banner(env)

    if args.env:
        print_env_info(env)
        return

    if args.triage_all:
        run_triage_all(args.output, args.html_output)
    elif args.process:
        result = run_process_triage()
        print_process_report(result)
        save_report({"processes": result}, args.output)
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
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

