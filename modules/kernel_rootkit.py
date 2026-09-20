# modules/kernel_rootkit.py
"""
SentinelX - Kernel Rootkit Detection
Detects hidden kernel modules and rootkit indicators.

Linux only. Requires cross-checking multiple sources:
- /proc/modules (kernel's view)
- /sys/module (sysfs view)
- lsmod output (userspace view)
- /proc/kallsyms (symbols)

Any discrepancy indicates DKOM (Direct Kernel Object Manipulation).
"""

import os
import re
import platform
import logging
import subprocess
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("SentinelX.kernel_rootkit")


# ============================================================
# Helpers
# ============================================================

def _is_linux():
    return platform.system().lower() == "linux"


def _run_cmd(cmd, timeout=10):
    """Run command safely."""
    try:
        result = subprocess.run(
            cmd,
            shell=isinstance(cmd, str),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    except Exception:
        return None


# ============================================================
# Module enumeration (multiple sources)
# ============================================================

def get_loaded_modules_lsmod():
    """Get modules via lsmod command."""
    output = _run_cmd("lsmod")
    if not output:
        return set()

    modules = set()
    for line in output.splitlines()[1:]:  # Skip header
        parts = line.split()
        if parts:
            modules.add(parts[0])
    return modules


def get_loaded_modules_proc():
    """Get modules from /proc/modules."""
    try:
        with open("/proc/modules") as f:
            modules = set()
            for line in f:
                parts = line.split()
                if parts:
                    modules.add(parts[0])
            return modules
    except (PermissionError, FileNotFoundError, OSError):
        return set()


def get_loaded_modules_sysfs():
    """Get modules from /sys/module."""
    modules = set()
    sys_module = Path("/sys/module")
    if not sys_module.exists():
        return modules

    try:
        for entry in sys_module.iterdir():
            if entry.is_dir():
                modules.add(entry.name)
    except PermissionError:
        pass
    return modules


def get_module_paths():
    """Get module file paths from /proc/modules."""
    paths = {}
    try:
        with open("/proc/modules") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    name = parts[0]
                    # Field 6 is the path (may be empty or (deleted))
                    if len(parts) >= 6:
                        path = parts[-1] if parts[-1].startswith("/") else None
                        paths[name] = path
    except (PermissionError, FileNotFoundError, OSError):
        pass
    return paths


# ============================================================
# Analysis
# ============================================================

def compare_module_lists():
    """Cross-check module lists from different sources."""
    lsmod_mods = get_loaded_modules_lsmod()
    proc_mods = get_loaded_modules_proc()
    sysfs_mods = get_loaded_modules_sysfs()

    # Sysfs includes built-in modules too — filter to those with 'initstate'
    real_sysfs = set()
    for mod in sysfs_mods:
        initstate = Path(f"/sys/module/{mod}/initstate")
        try:
            if initstate.exists():
                real_sysfs.add(mod)
        except Exception:
            pass

    # Compare
    discrepancies = {
        "lsmod": lsmod_mods,
        "proc": proc_mods,
        "sysfs": real_sysfs,
        "in_proc_not_lsmod": proc_mods - lsmod_mods,
        "in_lsmod_not_proc": lsmod_mods - proc_mods,
        "in_sysfs_not_proc": real_sysfs - proc_mods,
        "in_proc_not_sysfs": proc_mods - real_sysfs,
    }

    return discrepancies


def check_module_paths():
    """Check for modules loaded from suspicious paths."""
    suspicious = []
    paths = get_module_paths()

    # Suspicious locations
    bad_prefixes = ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/", "/home/"]

    for name, path in paths.items():
        if not path:
            continue

        # Deleted (indicates rootkit unloading)
        if "(deleted)" in path:
            suspicious.append({
                "module": name,
                "path": path,
                "reason": "Module loaded from deleted file (hidden rootkit indicator)",
                "severity": "CRITICAL",
            })
            continue

        # Suspicious prefix
        for prefix in bad_prefixes:
            if path.startswith(prefix):
                suspicious.append({
                    "module": name,
                    "path": path,
                    "reason": f"Loaded from suspicious location: {prefix}",
                    "severity": "HIGH",
                })
                break

    return suspicious


def check_module_signatures():
    """Check for unsigned modules (may indicate tampering)."""
    unsigned = []

    # Try modinfo to check signature
    lsmod_mods = get_loaded_modules_lsmod()

    for mod in list(lsmod_mods)[:50]:  # Limit for speed
        output = _run_cmd(f"modinfo {mod} 2>/dev/null", timeout=5)
        if output and "sig_id:" not in output.lower():
            unsigned.append({
                "module": mod,
                "reason": "No signature found",
                "severity": "MEDIUM",
            })

    return unsigned


def check_kallsyms_hidden():
    """
    Check /proc/kallsyms for suspicious symbols.
    Rootkits often hide symbols or add fake ones.
    """
    suspicious = []

    try:
        with open("/proc/kallsyms") as f:
            content = f.read()
    except (PermissionError, FileNotFoundError):
        return suspicious

    # Look for common rootkit signatures
    patterns = [
        (r"\bsys_call_table\b", "syscall table reference"),
        (r"\bhide_module\b", "module hiding function"),
        (r"\brootkit\b", "explicit rootkit name"),
        (r"\bhide_pid\b", "process hiding function"),
        (r"\bhide_file\b", "file hiding function"),
        (r"\bkeylogger\b", "keylogger indicator"),
    ]

    for pattern, desc in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            suspicious.append({
                "pattern": pattern,
                "matches": len(matches),
                "reason": desc,
                "severity": "MEDIUM",
            })

    return suspicious


def check_proc_modules_size():
    """Check if /proc/modules appears tampered."""
    warnings = []

    proc_modules = Path("/proc/modules")
    if not proc_modules.exists():
        warnings.append({
            "reason": "/proc/modules does not exist",
            "severity": "LOW",
        })
        return warnings

    try:
        size = proc_modules.stat().st_size
        if size == 0:
            warnings.append({
                "reason": "/proc/modules is empty (unusual)",
                "severity": "MEDIUM",
            })
    except Exception:
        pass

    return warnings


# ============================================================
# Main check
# ============================================================

def run_kernel_rootkit_check():
    """Full kernel rootkit check."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "platform": platform.platform(),
        "is_linux": _is_linux(),
        "module_counts": {},
        "discrepancies": {},
        "suspicious_paths": [],
        "unsigned_modules": [],
        "suspicious_symbols": [],
        "warnings": [],
        "summary": {},
    }

    if not _is_linux():
        result["error"] = "Kernel rootkit detection is Linux-only"
        return result

    # Module counts
    result["module_counts"] = {
        "lsmod": len(get_loaded_modules_lsmod()),
        "proc": len(get_loaded_modules_proc()),
        "sysfs": len(get_loaded_modules_sysfs()),
    }

    # Discrepancies
    disc = compare_module_lists()
    result["discrepancies"] = {
        "in_proc_not_lsmod": sorted(disc["in_proc_not_lsmod"]),
        "in_lsmod_not_proc": sorted(disc["in_lsmod_not_proc"]),
        "in_sysfs_not_proc": sorted(disc["in_sysfs_not_proc"]),
        "in_proc_not_sysfs": sorted(disc["in_proc_not_sysfs"]),
    }

    # Suspicious paths
    result["suspicious_paths"] = check_module_paths()

    # Unsigned modules
    result["unsigned_modules"] = check_module_signatures()

    # Kallsyms
    result["suspicious_symbols"] = check_kallsyms_hidden()

    # Proc size
    result["warnings"] = check_proc_modules_size()

    # Summary
    total_issues = (
        len(result["suspicious_paths"]) +
        len(result["unsigned_modules"]) +
        len(result["suspicious_symbols"]) +
        len(disc["in_proc_not_lsmod"]) +
        len(disc["in_lsmod_not_proc"]) +
        len(result["warnings"])
    )

    result["summary"] = {
        "modules_lsmod": result["module_counts"]["lsmod"],
        "modules_proc": result["module_counts"]["proc"],
        "modules_sysfs": result["module_counts"]["sysfs"],
        "suspicious_paths": len(result["suspicious_paths"]),
        "unsigned_modules": len(result["unsigned_modules"]),
        "hidden_modules": len(disc["in_proc_not_lsmod"]) + len(disc["in_lsmod_not_proc"]),
        "suspicious_symbols": len(result["suspicious_symbols"]),
        "total_issues": total_issues,
        "is_root": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
    }

    return result


# ============================================================
# Report
# ============================================================

def print_rootkit_report(result):
    print("\n" + "=" * 70)
    print("  Kernel Rootkit Detection Report - SentinelX")
    print("=" * 70)

    if not result.get("is_linux"):
        print(f"\n[!] {result.get('error', 'Not Linux')}")
        return

    s = result.get("summary", {})
    print(f"\n[*] Platform: {result.get('platform', '?')}")
    print(f"[*] Root: {'YES' if s.get('is_root') else 'no'}")
    print(f"[*] Modules (lsmod): {s.get('modules_lsmod', 0)}")
    print(f"[*] Modules (/proc): {s.get('modules_proc', 0)}")
    print(f"[*] Modules (/sys): {s.get('modules_sysfs', 0)}")

    # Hidden modules (highest priority)
    hidden = s.get("hidden_modules", 0)
    if hidden > 0:
        print(f"\n[!] 🔴 HIDDEN MODULES DETECTED: {hidden}")
        disc = result.get("discrepancies", {})
        if disc.get("in_proc_not_lsmod"):
            print(f"\n    In /proc but NOT in lsmod (hidden from userspace):")
            for m in disc["in_proc_not_lsmod"][:10]:
                print(f"      🔴 {m}")
        if disc.get("in_lsmod_not_proc"):
            print(f"\n    In lsmod but NOT in /proc (unusual):")
            for m in disc["in_lsmod_not_proc"][:10]:
                print(f"      ⚠ {m}")
    else:
        print(f"\n[✓] No hidden modules detected")

    # Suspicious paths
    if result.get("suspicious_paths"):
        print(f"\n[!] Suspicious module paths:")
        for item in result["suspicious_paths"][:10]:
            marker = "🔴" if item["severity"] == "CRITICAL" else "⚠"
            print(f"    {marker} {item['module']}: {item['path']}")
            print(f"       {item['reason']}")

    # Unsigned
    if result.get("unsigned_modules"):
        print(f"\n[i] Unsigned modules: {len(result['unsigned_modules'])}")
        for item in result["unsigned_modules"][:5]:
            print(f"    - {item['module']}")

    # Symbols
    if result.get("suspicious_symbols"):
        print(f"\n[!] Suspicious symbols in kallsyms:")
        for item in result["suspicious_symbols"]:
            print(f"    ⚠ {item['reason']}: {item['matches']} matches")

    # Warnings
    if result.get("warnings"):
        print(f"\n[!] Warnings:")
        for w in result["warnings"]:
            print(f"    - {w['reason']}")

    # Verdict
    if s.get("total_issues", 0) == 0:
        print(f"\n[✓] No rootkit indicators detected")
    else:
        print(f"\n[!] Total issues: {s['total_issues']}")

    print("\n" + "=" * 70 + "\n")


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    if not _is_linux():
        print(f"[!] Kernel rootkit detection requires Linux")
        print(f"    Current platform: {platform.system()}")
        print()
        print("[i] On Termux/Android:")
        print(f"    - This module will not work fully")
        print(f"    - Android has different kernel architecture")
        print(f"    - Use on Kali/WSL/Linux instead")
        import sys
        sys.exit(0)

    result = run_kernel_rootkit_check()
    print_rootkit_report(result)
