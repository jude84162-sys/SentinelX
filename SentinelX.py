#!/usr/bin/env python3
"""
SentinelX - Modular Enterprise Blue Team Suite (v2.0.0)
Cross-platform: Termux, WSL, Kali, Linux, macOS, Windows, Docker.

20 integrated modules for complete security triage.
"""

import json
import argparse
import logging
from datetime import datetime
from pathlib import Path

# Environment
from modules.env_detect import get_environment, get_env_label, print_env_info

# Core
from modules.process import run_process_triage, print_process_report
from modules.network import run_network_analysis, print_network_report
from modules.files import run_file_triage, print_file_report
from modules.persistence import run_persistence_check, print_persistence_report
from modules.resources import run_resource_check, print_resource_report

# Detection
from modules.ioc_hunter import scan_path as ioc_scan, print_ioc_report

try:
    from modules.yara_engine import (
        scan_directory as yara_scan,
        scan_file as yara_scan_file,
        print_yara_report,
        HAS_YARA,
    )
except ImportError:
    HAS_YARA = False

try:
    from modules.virustotal import (
        check_file as vt_check,
        check_hash as vt_check_hash,
        print_vt_report,
        is_api_key_valid as vt_has_key,
    )
except ImportError:
    vt_has_key = lambda: False

try:
    from modules.memory_scan import (
        scan_all_processes as memory_scan,
        print_memory_report,
        _is_linux as memory_supported,
    )
except ImportError:
    memory_supported = lambda: False

try:
    from modules.self_update import (
        check_for_update,
        update as self_update,
        print_update_status,
        do_update_and_print,
    )
except ImportError:
    pass

# Android
from modules.network_android import (
    run_android_network_triage,
    print_android_network_report,
)
from modules.android_osint import (
    run_android_osint,
    print_android_osint_report,
)
from modules.android_spyware import (
    run_android_spyware_check,
    print_android_spyware_report,
)

# Notifications
from modules.notify import send_summary_notification as android_summary
from modules.desktop_notify import (
    send_summary_notification as desktop_summary,
    notify as desktop_notify,
)

# OSINT
from modules.phone_osint import analyze_phone_number, print_phone_report

# HTML
from modules.html_report import generate_html_report

# Daemon
from modules.daemon import (
    start_daemon,
    stop_daemon,
    daemon_status,
    _run_full_scan as daemon_scan_once,
)

logger = logging.getLogger("SentinelX")

BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

VERSION = "2.0.0"


def configure_logging(quiet=False, verbose=False):
    """Configure logging level."""
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        force=True,
    )
    logging.getLogger("SentinelX").setLevel(level)

    import warnings
    warnings.filterwarnings("ignore", category=RuntimeWarning, module="psutil")


def print_banner(env):
    label = get_env_label(env)
    print("=" * 75)
    print("       SentinelX - Modular Enterprise Blue Team Suite")
    print(f"       Environment: {label}  |  v{VERSION}")
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
    """Send native notification."""
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


def _get_download_dirs():
    """Get download directories per platform."""
    import os
    import platform as _plat
    system = _plat.system().lower()
    home = os.path.expanduser("~")

    if "android" in _plat.platform().lower():
        return [
            os.path.expanduser("~/storage/shared/Download"),
            "/storage/emulated/0/Download",
        ]
    if system == "windows":
        return [f"{home}\\Downloads"]
    if system == "darwin":
        return [f"{home}/Downloads"]
    return [f"{home}/Downloads"]


def run_triage_all(output_file="full_triage_report.json", html=False):
    """Run full triage with all modules."""
    env = get_environment()
    import os

    report_data = {
        "timestamp": datetime.now().isoformat(),
        "version": VERSION,
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

    # 1. Process
    if env["capabilities"]["process_triage"]:
        logger.info("[*] Running Deep Process Triage...")
        report_data["processes"] = run_process_triage()
        print_process_report(report_data["processes"])

    # 2. Resources
    logger.info("[*] Checking System Resources...")
    report_data["resources"] = run_resource_check()
    print_resource_report(report_data["resources"])

    # 3. Network
    logger.info("[*] Analyzing Active Network Connections...")
    report_data["network"] = run_network_analysis()
    print_network_report(report_data["network"])

    # 4. Files
    logger.info("[*] Scanning File System for Suspicious Files...")
    report_data["files"] = run_file_triage()
    print_file_report(report_data["files"])

    # 5. Persistence
    logger.info("[*] Checking Persistence Mechanisms...")
    report_data["persistence"] = run_persistence_check()
    print_persistence_report(report_data["persistence"])

    # 6. IOC Hunter
    logger.info("[*] Running IOC Hunt on Download folders...")
    for dl_dir in _get_download_dirs():
        if os.path.isdir(dl_dir):
            try:
                result = ioc_scan(dl_dir)
                report_data["ioc_hunter"] = result
                print_ioc_report(result)
                break
            except Exception as e:
                logger.warning(f"    IOC scan failed: {e}")

    # 7. YARA
    if HAS_YARA:
        logger.info("[*] Running YARA Engine scan...")
        for dl_dir in _get_download_dirs():
            if os.path.isdir(dl_dir):
                try:
                    yara_result = yara_scan(dl_dir, max_files=1000)
                    report_data["yara"] = yara_result
                    print_yara_report(yara_result)
                    break
                except Exception as e:
                    logger.warning(f"    YARA scan failed: {e}")

    # 8. Memory (Linux only)
    if memory_supported():
        logger.info("[*] Running Memory Scan...")
        try:
            mem_result = memory_scan()
            report_data["memory"] = mem_result
            print_memory_report(mem_result)
        except Exception as e:
            logger.warning(f"    Memory scan failed: {e}")

    # 9. Android
    if env["is_android"]:
        logger.info("[*] Running Android OSINT...")
        report_data["android_osint"] = run_android_osint()
        print_android_osint_report(report_data["android_osint"])

        if env["has_termux_api"]:
            logger.info("[*] Running Android Network Triage...")
            report_data["android_network"] = run_android_network_triage()
            print_android_network_report(report_data["android_network"])

            logger.info("[*] Running Android Spyware Detection...")
            report_data["android_spyware"] = run_android_spyware_check()
            print_android_spyware_report(report_data["android_spyware"])

    # Save
    save_report(report_data, output_file)

    # HTML
    if html:
        try:
            html_name = output_file.replace(".json", ".html")
            html_path = OUTPUT_DIR / html_name
            generate_html_report(report_data, html_path)
            print(f"\n[+] HTML Dashboard: {html_path}")
            print(f"    Open: termux-open {html_path}")
        except Exception as e:
            logger.warning(f"HTML generation failed: {e}")

    # Notification
    _send_notification(env, report_data)

    return report_data


def main():
    parser = argparse.ArgumentParser(
        description="SentinelX v2.0.0 - Blue Team Security Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Core
    parser.add_argument("--triage-all", action="store_true", help="Run all modules")
    parser.add_argument("--process", action="store_true", help="Process analysis")
    parser.add_argument("--resources", action="store_true", help="Resource monitor")
    parser.add_argument("--network", action="store_true", help="Network analysis")
    parser.add_argument("--files", action="store_true", help="File triage")
    parser.add_argument("--persistence", action="store_true", help="Persistence check")

    # Detection
    parser.add_argument("--ioc", type=str, default=None, metavar="PATH",
                        help="IOC hash scan")
    parser.add_argument("--yara", type=str, default=None, metavar="PATH",
                        help="YARA scan (advanced rules)")
    parser.add_argument("--vt", type=str, default=None, metavar="FILE",
                        help="VirusTotal check (needs VT_API_KEY)")
    parser.add_argument("--memory", action="store_true",
                        help="Memory scan (Linux only)")

    # Android
    parser.add_argument("--android", action="store_true", help="Android OSINT")
    parser.add_argument("--android-network", action="store_true", help="Android network")
    parser.add_argument("--spyware", action="store_true", help="Android spyware")

    # OSINT
    parser.add_argument("--phone", type=str, default=None,
                        help="Analyze phone number")

    # Daemon
    parser.add_argument("--daemon", action="store_true", help="Start daemon")
    parser.add_argument("--daemon-stop", action="store_true", help="Stop daemon")
    parser.add_argument("--daemon-status", action="store_true", help="Daemon status")
    parser.add_argument("--scan-once", action="store_true", help="Single scan")

    # Update
    parser.add_argument("--update", action="store_true",
                        help="Check for updates")
    parser.add_argument("--update-now", action="store_true",
                        help="Update SentinelX now")

    # Info
    parser.add_argument("--notify-test", action="store_true", help="Test notifications")
    parser.add_argument("--env", action="store_true", help="Environment info")

    # Output
    parser.add_argument("--html", action="store_true", help="Generate HTML dashboard")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")
    parser.add_argument("--output", type=str, default="full_triage_report.json")
    parser.add_argument("--version", action="version", version=f"SentinelX {VERSION}")

    args = parser.parse_args()

    configure_logging(quiet=args.quiet, verbose=args.verbose)

    env = get_environment()
    print_banner(env)

    # ============================================================
    # Update commands
    # ============================================================
    if args.update:
        print_update_status()
        return

    if args.update_now:
        do_update_and_print()
        return

    # ============================================================
    # Daemon
    # ============================================================
    if args.daemon:
        print("[*] Starting SentinelX daemon...")
        start_daemon()
        return

    if args.daemon_stop:
        stop_daemon()
        return

    if args.daemon_status:
        daemon_status()
        return

    if args.scan_once:
        print("[*] Running single scan cycle...")
        daemon_scan_once()
        print("[+] Scan complete.")
        return

    # ============================================================
    # Info
    # ============================================================
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

    # ============================================================
    # OSINT
    # ============================================================
    if args.phone:
        result = analyze_phone_number(args.phone)
        print_phone_report(result)
        save_report({"phone_osint": result}, args.output)

        if (result.get("valid") and
                result["summary"]["risk_level"] in ("HIGH", "CRITICAL")):
            if env["has_desktop_notify"]:
                desktop_notify(
                    "Phone Risk Detected",
                    f"{result['summary']['e164']} - {result['summary']['risk_level']}",
                    urgency="normal"
                )
        return

    # ============================================================
    # IOC Hunter
    # ============================================================
    if args.ioc:
        import os
        target = os.path.expanduser(args.ioc)
        if not os.path.exists(target):
            print(f"Error: {target} not found")
            return
        result = ioc_scan(target)
        print_ioc_report(result)
        save_report({"ioc_scan": result}, args.output)
        return

    # ============================================================
    # YARA
    # ============================================================
    if args.yara:
        import os
        target = os.path.expanduser(args.yara)
        if not os.path.exists(target):
            print(f"Error: {target} not found")
            return
        if not HAS_YARA:
            print("[!] yara-python not installed.")
            print("    Run: pip install yara-python")
            return
        if os.path.isfile(target):
            matches = yara_scan_file(target)
            result = {"target": target, "scanned": 1, "matches": matches}
        else:
            result = yara_scan(target)
        print_yara_report(result)
        save_report({"yara": result}, args.output)
        return

    # ============================================================
    # VirusTotal
    # ============================================================
    if args.vt:
        import os
        target = os.path.expanduser(args.vt)
        if os.path.isfile(target):
            result = vt_check(target)
        else:
            result = vt_check_hash(args.vt)
        print_vt_report(result)
        return

    # ============================================================
    # Memory
    # ============================================================
    if args.memory:
        if not memory_supported():
            print("[!] Memory scanning only supported on Linux")
            return
        result = memory_scan()
        print_memory_report(result)
        return

    # ============================================================
    # Module-specific
    # ============================================================
    if args.triage_all:
        run_triage_all(args.output, html=args.html)
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
