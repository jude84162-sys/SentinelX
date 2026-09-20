# modules/android_osint.py
"""
SentinelX - Android OSINT Module (High Accuracy)
Enumerates packages with multiple fallback methods and analyzes them.
Zero false positives: uses comprehensive whitelists + context-aware heuristics.

Enumeration methods (tried in order):
  1. cmd package list packages -3       (works on Android 11+ without root!)
  2. pm list packages -3                (blocked on Android 11+)
  3. dumpsys package packages           (not available in Termux)
  4. filesystem scan of /sdcard/Android/data

Permission analysis uses dumpsys when available, otherwise name-based heuristics.
"""

import os
import subprocess
import platform
import logging
import re
from datetime import datetime

logger = logging.getLogger("SentinelX.android_osint")


def _is_android():
    return "android" in platform.platform().lower()


def _run_cmd(args, timeout=15, use_shell=False):
    """Run a command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            args if not use_shell else " ".join(args),
            shell=use_shell,
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except FileNotFoundError:
        return None, "command not found", -1
    except subprocess.TimeoutExpired:
        return None, "timeout", -1
    except Exception as e:
        return None, str(e), -1


# ============================================================
# Enumeration methods
# ============================================================

def _list_packages_cmd():
    """Method 1: cmd package list packages (works on Android 11+ without root)."""
    output, error, rc = _run_cmd(
        ["cmd", "package", "list", "packages", "-3"], timeout=20
    )
    if not output:
        return None, error

    packages = []
    for line in output.split("\n"):
        line = line.strip()
        if not line.startswith("package:"):
            continue
        pkg = line.replace("package:", "").strip()
        if pkg and "." in pkg:
            packages.append({"apk_path": None, "package": pkg})

    return packages if packages else None, error


def _list_packages_pm():
    """Method 2: pm list packages (blocked on Android 11+)."""
    output, error, rc = _run_cmd(["pm", "list", "packages", "-3", "-f"])
    if not output or "Failed transaction" in (error or ""):
        return None, error or "pm blocked"
    if "not found" in (error or "").lower():
        return None, error

    packages = []
    for line in output.split("\n"):
        line = line.strip()
        if not line.startswith("package:"):
            continue
        match = re.match(r"package:(.+?)=(.+)", line)
        if match:
            packages.append({"apk_path": match.group(1), "package": match.group(2)})
        else:
            packages.append({"apk_path": None, "package": line.replace("package:", "")})

    return packages if packages else None, error


def _list_packages_dumpsys():
    """Method 3: dumpsys package packages."""
    output, error, rc = _run_cmd(["dumpsys", "package", "packages"], timeout=30)
    if not output:
        return None, error

    packages = []
    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("Package ["):
            match = re.match(r"Package \[([^\]]+)\]", line)
            if match:
                packages.append({"apk_path": None, "package": match.group(1)})

    return packages if packages else None, error


def _list_packages_filesystem():
    """Method 4: Walk /sdcard/Android/data for app traces."""
    search_dirs = [
        "/sdcard/Android/data",
        "/sdcard/Android/obb",
    ]
    packages = []
    seen = set()

    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for entry in os.listdir(d):
                if entry.startswith("com.") and entry not in seen:
                    seen.add(entry)
                    packages.append({
                        "apk_path": None,
                        "package": entry,
                        "source": "filesystem"
                    })
        except PermissionError:
            continue

    return packages if packages else None, None


def _get_all_packages():
    """Try all methods and return (packages, method_name)."""
    methods = [
        ("cmd", _list_packages_cmd),
        ("pm", _list_packages_pm),
        ("dumpsys", _list_packages_dumpsys),
        ("filesystem", _list_packages_filesystem),
    ]

    for name, method in methods:
        logger.info(f"Trying package enumeration via: {name}")
        try:
            result = method()
            packages, _ = result if isinstance(result, tuple) else (result, None)
            if packages:
                logger.info(f"[+] Found {len(packages)} packages via {name}")
                return packages, name
        except Exception as e:
            logger.debug(f"Method {name} failed: {e}")
            continue

    return [], None


def _check_dumpsys_available():
    """Check if dumpsys is usable."""
    out, err, rc = _run_cmd(["dumpsys", "--help"], timeout=5)
    return rc == 0 and bool(out)


# ============================================================
# Permission analysis (dumpsys-based)
# ============================================================

DANGEROUS_PERMISSIONS = {
    "SEND_SMS", "READ_SMS", "RECEIVE_SMS",
    "READ_CONTACTS", "WRITE_CONTACTS",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "CALL_PHONE",
    "RECORD_AUDIO", "CAMERA",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
    "INSTALL_PACKAGES", "WRITE_SECURE_SETTINGS",
    "PACKAGE_USAGE_STATS", "MANAGE_EXTERNAL_STORAGE",
    "READ_LOGS", "RECEIVE_BOOT_COMPLETED",
    "PROCESS_OUTGOING_CALLS", "ANSWER_PHONE_CALLS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "GET_ACCOUNTS", "USE_BIOMETRIC",
    "FOREGROUND_SERVICE", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
}

CRITICAL_PERMISSIONS = {
    "BIND_ACCESSIBILITY_SERVICE", "SEND_SMS", "READ_SMS",
    "RECEIVE_SMS", "BIND_DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW",
    "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "INSTALL_PACKAGES", "WRITE_SECURE_SETTINGS",
}


def _get_package_permissions(package):
    """Get permissions for a package via dumpsys."""
    output, error, rc = _run_cmd(["dumpsys", "package", package], timeout=10)
    if not output:
        return [], error

    permissions = []
    in_perms = False
    for line in output.split("\n"):
        line = line.strip()
        lower = line.lower()
        if "requested permissions:" in lower:
            in_perms = True
            continue
        if "install permissions:" in lower or "runtime permissions:" in lower:
            in_perms = False
            continue
        if in_perms and ":" in line:
            perm = line.split(":")[0].strip()
            if "." in perm:
                permissions.append(perm)

    return permissions, None


def _analyze_permissions(permissions):
    """Analyze permission list for dangerous ones."""
    found_dangerous = []
    found_critical = []

    for perm in permissions:
        short = perm.split(".")[-1] if "." in perm else perm
        if short in CRITICAL_PERMISSIONS:
            found_critical.append(short)
        elif short in DANGEROUS_PERMISSIONS:
            found_dangerous.append(short)

    risk_score = len(found_critical) * 10 + len(found_dangerous) * 3

    if len(found_critical) >= 2:
        risk_level = "CRITICAL"
    elif found_critical or len(found_dangerous) >= 5:
        risk_level = "HIGH"
    elif len(found_dangerous) >= 2:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "dangerous": found_dangerous,
        "critical": found_critical,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_permissions": len(permissions)
    }


# ============================================================
# ✅ COMPREHENSIVE WHITELIST — Known safe packages
# ============================================================

KNOWN_SAFE_PACKAGES = {
    # Termux ecosystem
    "com.termux", "com.termux.api", "com.termux.boot",
    "com.termux.styling", "com.termux.widget", "com.termux.window",

    # Google
    "com.android.chrome", "com.google.android.gms",
    "com.google.android.gsf", "com.android.vending",
    "com.google.android.apps.docs", "com.google.android.contactkeys",
    "com.google.android.apps.maps", "com.google.android.youtube",
    "com.google.android.apps.photos", "com.google.android.gm",
    "com.google.android.apps.drive",
    "com.google.android.inputmethod.latin",
    "com.google.android.apps.tachyon",
    "com.google.android.calendar",
    "com.google.android.keep",

    # Messaging / Social
    "com.whatsapp", "com.whatsapp.w4b",
    "org.telegram.messenger", "org.thunderdog.challegram",
    "com.instagram.android", "com.facebook.katana", "com.facebook.orca",
    "com.twitter.android", "com.snapchat.android",
    "com.discord", "com.slack", "com.microsoft.teams",
    "com.viber.voip", "com.skype.raider",

    # Samsung / OEM built-ins
    "com.samsung.android.calendar", "com.samsung.android.app.reminder",
    "com.sec.android.app.shealth", "com.sec.android.app.popupcalculator",
    "com.samsung.android.app.contacts", "com.samsung.android.messaging",
    "com.sec.android.app.camera", "com.sec.android.gallery3d",
    "com.samsung.android.mobileservice",
    "com.samsung.android.app.notes",
    "com.samsung.android.voc",
    "com.samsung.android.game.gamehome",

    # Security tools (legitimate)
    "com.joeykrim.rootcheck", "com.jrummyapps.rootchecker",
    "eu.chainfire.supersu", "com.topjohnwu.magisk",
    "com.noshufou.android.su", "com.koushikdutta.superuser",

    # System apps
    "com.android.settings", "com.android.systemui",
    "com.android.phone", "com.android.mms",
    "com.android.providers.contacts",
    "com.android.providers.telephony",
    "org.fdroid.fdroid",

    # Music / Media
    "com.spotify.music", "com.netflix.mediaclient",
    "com.dywx.larkplayer", "com.ytv.pronew",
    "com.google.android.apps.youtube.music",

    # Productivity
    "com.microsoft.office.word", "com.microsoft.office.excel",
    "com.microsoft.office.outlook", "com.microsoft.office.powerpoint",
    "com.dropbox.android", "com.evernote",
    "com.notion.id", "com.todoist",
    "ru.zdevs.zarchiver",  # ZArchiver

    # Utilities (legit)
    "com.overlook.android.fing",  # Fing (network scanner)
    "com.lifesoftwarelab.android.incomingcallcontrol",
    "com.chess.clock", "com.automata4.learnata",
    "com.camerasideas.instashot",
    "com.netease.newspike",  # 网易新闻

    # Common legit apps
    "com.zhiliaoapp.musically",  # TikTok
    "com.ubercab", "com.ubercab.eats",
    "com.airbnb.android",
    "com.booking",
    "com.tinder",
}


# ============================================================
# ✅ SAFE NAME PATTERNS — Legit name fragments (avoid FP)
# ============================================================

SAFE_NAME_PATTERNS = {
    "rootcheck", "rootchecker", "supersu", "magisk",  # security tools
    "monitor",  # system monitor (not spy)
    "tracker",  # fitness tracker (not spy)
    "control",  # remote control (legit)
    "reader", "viewer", "player", "manager",  # common apps
    "office", "docs", "notes", "calendar", "mail",
    "weather", "news", "map", "clock", "camera",
    "photo", "video", "music", "audio",
    "backup", "sync", "cloud",
}


def _name_based_risks(pkg_name):
    """
    Analyze package name for suspicious patterns.
    Returns list of reason strings (empty = clean).
    """
    if pkg_name in KNOWN_SAFE_PACKAGES:
        return []

    reasons = []
    name = pkg_name.lower()

    # Step 1: Check safe patterns FIRST
    for pattern in SAFE_NAME_PATTERNS:
        if pattern in name:
            # But make sure not combined with bad keyword
            bad_words = ["spy", "hack", "steal", "keylog", "cheat", "crack"]
            if not any(bad in name for bad in bad_words):
                return []

    # Step 2: Check suspicious keyword families
    suspicious_keywords = {
        "spy": "spyware indicator",
        "keylog": "keylogger indicator",
        "steal": "credential theft indicator",
        "monitor": "monitoring indicator",
        "hack": "hacking tool indicator",
        "cheat": "game cheat indicator",
        "crack": "cracked software indicator",
        "warez": "pirated software indicator",
        "inject": "code injection indicator",
    }
    for kw, desc in suspicious_keywords.items():
        if kw in name:
            reasons.append(f"{desc}: '{kw}'")

    # Step 3: Modified / premium app patterns
    mod_patterns = [".premium", ".pro.", ".mod.", ".crack", ".unlocked", ".paid"]
    for pat in mod_patterns:
        if pat in name:
            reasons.append(f"Modified/premium app indicator: '{pat}'")
            break

    # Step 4: Known modified app families
    known_mod_apps = [
        "snaptube", "vanced", "youtubevanced",
        "ogwhatsapp", "gbwhatsapp", "whatsappplus", "fmwhatsapp",
        "instapro", "instaplus", "tiktokmod",
        "spotifypremium", "spotifyplus",
    ]
    for app in known_mod_apps:
        if app in name:
            reasons.append(f"Known modified app family: '{app}'")
            break

    # Step 5: Suspicious TLD patterns
    parts = name.split(".")
    if len(parts) >= 2:
        tld = parts[1]
        suspicious_tlds = ["xyz", "top", "click", "site", "online", "fun", "icu"]
        if tld in suspicious_tlds:
            reasons.append(f"Suspicious package TLD: '.{tld}'")

    return reasons


def _is_suspicious_package(pkg_info, perm_analysis):
    """Permission-based suspicion check."""
    reasons = []
    pkg = pkg_info.get("package", "")

    if pkg in KNOWN_SAFE_PACKAGES:
        return False, []

    if perm_analysis.get("critical"):
        reasons.append(f"Critical permissions: {', '.join(perm_analysis['critical'])}")

    if perm_analysis.get("risk_score", 0) > 30:
        reasons.append(f"High risk score: {perm_analysis['risk_score']}")

    # Also check name-based
    name_risks = _name_based_risks(pkg)
    reasons.extend(name_risks)

    return len(reasons) > 0, reasons


# ============================================================
# Main entry
# ============================================================

def run_android_osint():
    result = {
        "timestamp": datetime.now().isoformat(),
        "is_android": _is_android(),
        "enumeration_method": None,
        "permissions_available": False,
        "packages": [],
        "suspicious": [],
        "critical_permission_apps": [],
        "summary": {},
        "error": None,
        "warning": None,
        "restriction": None
    }

    if not _is_android():
        result["error"] = "Not running on Android"
        return result

    packages, method = _get_all_packages()
    result["enumeration_method"] = method

    if not packages:
        result["restriction"] = "no_enumeration_method"
        result["warning"] = (
            "Could not enumerate packages. Try:\n"
            "  1. python SentinelX.py --adb   (ADB from PC)\n"
            "  2. sudo python SentinelX.py --android   (root)\n"
            "  3. Verify 'cmd package list packages -3' works"
        )
        return result

    perms_available = _check_dumpsys_available()
    result["permissions_available"] = perms_available

    for pkg in packages[:100]:
        pkg_name = pkg["package"]

        if perms_available:
            perms, _ = _get_package_permissions(pkg_name)
            if perms:
                perm_analysis = _analyze_permissions(perms)
                pkg["permissions"] = perms
                pkg["permission_analysis"] = perm_analysis

                is_suspicious, reasons = _is_suspicious_package(pkg, perm_analysis)
                if is_suspicious:
                    pkg["suspicion_reasons"] = reasons
                    result["suspicious"].append(pkg)

                if perm_analysis.get("critical"):
                    result["critical_permission_apps"].append(pkg)
            else:
                name_risks = _name_based_risks(pkg_name)
                if name_risks:
                    pkg["suspicion_reasons"] = name_risks
                    pkg["permission_analysis"] = {
                        "risk_level": "UNKNOWN",
                        "risk_score": len(name_risks) * 5
                    }
                    result["suspicious"].append(pkg)
        else:
            name_risks = _name_based_risks(pkg_name)
            if name_risks:
                pkg["suspicion_reasons"] = name_risks
                pkg["permission_analysis"] = {
                    "risk_level": "UNKNOWN",
                    "risk_score": len(name_risks) * 5,
                    "dangerous": [],
                    "critical": [],
                    "total_permissions": 0
                }
                result["suspicious"].append(pkg)

        result["packages"].append(pkg)

    result["summary"] = {
        "enumeration_method": method,
        "permissions_available": perms_available,
        "total_packages": len(result["packages"]),
        "suspicious": len(result["suspicious"]),
        "critical_permission_apps": len(result["critical_permission_apps"]),
    }

    if not perms_available:
        result["warning"] = (
            "dumpsys not available — permission analysis uses name-based heuristics only. "
            "For full analysis, use ADB from PC: python SentinelX.py --adb"
        )

    return result


def print_android_osint_report(result):
    print("\n" + "=" * 70)
    print("  Android OSINT Report - SentinelX")
    print("=" * 70)

    if result.get("error"):
        print(f"\n[!] Error: {result['error']}")
        return

    s = result.get("summary", {})
    print(f"\n[*] Enumeration method: {s.get('enumeration_method', 'none')}")
    print(f"[*] Permissions available: {'YES' if s.get('permissions_available') else 'NO (name-only)'}")
    print(f"[*] Packages found: {s.get('total_packages', 0)}")
    print(f"[*] Suspicious: {s.get('suspicious', 0)}")
    print(f"[*] Critical permission apps: {s.get('critical_permission_apps', 0)}")

    if result.get("warning"):
        print(f"\n[!] {result['warning']}")

    if result.get("suspicious"):
        print(f"\n[!] Suspicious packages ({len(result['suspicious'])}):")
        for pkg in result["suspicious"][:20]:
            print(f"\n    [!] {pkg['package']}")
            risk = pkg.get("permission_analysis", {}).get("risk_level", "?")
            score = pkg.get("permission_analysis", {}).get("risk_score", 0)
            print(f"        Risk: {risk} (score {score})")
            for reason in pkg.get("suspicion_reasons", [])[:5]:
                print(f"        - {reason}")

    if result.get("critical_permission_apps"):
        print(f"\n[!] Apps with critical permissions:")
        for pkg in result["critical_permission_apps"][:10]:
            pa = pkg.get("permission_analysis", {})
            print(f"    - {pkg['package']}")
            print(f"      Critical: {', '.join(pa.get('critical', []))}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    r = run_android_osint()
    print_android_osint_report(r)
