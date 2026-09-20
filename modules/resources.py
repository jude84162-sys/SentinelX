# modules/resources.py
"""
SentinelX - Resource Monitor (High-Accuracy Version)
Tracks CPU, memory, battery, thermal.
Optimized: fast, accurate, no false positives.
"""

import os
import json
import time
import platform
import subprocess
import logging
import warnings
from datetime import datetime
from pathlib import Path

warnings.filterwarnings("ignore", category=RuntimeWarning, module="psutil")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = logging.getLogger("SentinelX.resources")


# ============================================================
# WHITELISTS — Known safe processes (avoid false positives)
# ============================================================

SAFE_PROCESS_NAMES = {
    # Android/Termux
    "com.termux", "com.termux.api", "com.termux.boot", "com.termux.widget",
    "termux-api", "bash", "sh", "python", "python3", "grep", "awk",
    "sed", "find", "ls", "cat", "echo", "sleep",
    # System
    "systemd", "init", "kernel", "kworker", "ksoftirqd", "migration",
    "rcu_sched", "rcu_gp", "watchdog", "kthreadd", "system_server",
    # Desktop apps (normal high CPU)
    "chrome", "firefox", "chromium", "safari", "code", "vim", "nvim",
    "nvim-qt", "emacs", "gedit", "kate", "atom",
    # Common tools
    "git", "npm", "node", "pip", "cargo", "go", "java", "gcc",
    # Compositors
    "gnome-shell", "kwin", "mutter", "xfwm4", "plasmashell",
    # Windows (WSL)
    "explorer.exe", "svchost.exe", "wininit.exe",
}

SAFE_PROCESS_PREFIXES = (
    "systemd-", "kworker/", "ksoftirqd/", "rcu_", "irq/",
    "dbus-", "gvfsd-", "pulseaudio", "pipewire",
)

# CPU threshold for "high usage" alert
CPU_ALERT_THRESHOLD = 40.0  # %
MEMORY_ALERT_THRESHOLD = 25.0  # %
DISK_WARN_THRESHOLD = 85.0  # %
DISK_CRIT_THRESHOLD = 95.0  # %


# ============================================================
# Helpers
# ============================================================

def _is_android():
    return "android" in platform.platform().lower()


def _is_safe_process(name):
    """Check if a process name is known-safe."""
    if not name:
        return True
    n = name.lower()
    if n in SAFE_PROCESS_NAMES:
        return True
    for prefix in SAFE_PROCESS_PREFIXES:
        if n.startswith(prefix):
            return True
    return False


def _run_cmd(cmd, timeout=10):
    """Run command safely."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    except Exception:
        return None


def _safe_psutil(func, *args, default=None, **kwargs):
    """Safely call psutil (Android may block /proc files)."""
    try:
        return func(*args, **kwargs)
    except (PermissionError, FileNotFoundError, OSError, RuntimeError) as e:
        logger.debug(f"psutil call failed: {e}")
        return default


# ============================================================
# Battery
# ============================================================

def get_battery_info():
    if not _is_android():
        return None

    output = _run_cmd(["termux-battery-status"], timeout=10)
    if not output:
        return None

    try:
        data = json.loads(output)
        return {
            "percentage": data.get("percentage"),
            "status": data.get("status"),
            "plugged": data.get("plugged"),
            "temperature": data.get("temperature"),
            "voltage": data.get("voltage"),
            "health": data.get("health"),
        }
    except json.JSONDecodeError:
        return None


# ============================================================
# Thermal
# ============================================================

def get_thermal_info():
    temps = {}

    if _is_android():
        output = _run_cmd(["termux-battery-status"], timeout=5)
        if output:
            try:
                data = json.loads(output)
                if "temperature" in data:
                    temps["battery"] = data["temperature"]
            except Exception:
                pass

    thermal_base = Path("/sys/class/thermal")
    if thermal_base.exists():
        try:
            for zone in thermal_base.glob("thermal_zone*"):
                try:
                    ztype = (zone / "type").read_text().strip()
                    ztemp = int((zone / "temp").read_text().strip()) / 1000.0
                    temps[ztype] = round(ztemp, 1)
                except (PermissionError, ValueError, OSError):
                    continue
        except Exception:
            pass

    if HAS_PSUTIL and hasattr(psutil, "sensors_temperatures"):
        try:
            for name, entries in psutil.sensors_temperatures().items():
                for e in entries:
                    key = f"{name}_{e.label}" if e.label else name
                    temps[key] = e.current
        except Exception:
            pass

    return temps


# ============================================================
# Top processes — accurate, filtered
# ============================================================

def get_top_processes(limit=10):
    """
    Get top CPU and memory processes.
    Filters: safe processes, low-usage noise.
    Uses 2-pass for accurate CPU reading.
    """
    if not HAS_PSUTIL:
        return {"cpu": [], "memory": []}

    # Pass 1: initialize CPU counters
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username']):
        try:
            p.cpu_percent()  # initialize
            procs.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Wait for accurate measurement
    time.sleep(1.0)

    # Pass 2: read actual values
    results = []
    for p in procs:
        try:
            info = p.info
            name = info.get('name') or "?"

            cpu = p.cpu_percent() or 0
            mem = p.memory_percent() or 0

            # Filter noise
            if cpu < 0.5 and mem < 0.5:
                continue

            # Filter safe processes from CPU list (but keep if MEM high)
            is_safe = _is_safe_process(name)

            results.append({
                "pid": info.get('pid'),
                "name": name,
                "user": info.get('username') or "?",
                "cpu": round(cpu, 2),
                "memory": round(mem, 2),
                "is_safe": is_safe,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    # Top CPU: only flag unsafe ones if CPU > threshold
    # But always show top overall
    by_cpu = sorted(results, key=lambda x: x["cpu"], reverse=True)
    by_cpu = [p for p in by_cpu if p["cpu"] > 1.0][:limit]

    by_mem = sorted(results, key=lambda x: x["memory"], reverse=True)
    by_mem = [p for p in by_mem if p["memory"] > 1.0][:limit]

    return {"cpu": by_cpu, "memory": by_mem}


# ============================================================
# Disk usage — accurate on Android
# ============================================================

def get_disk_usage():
    """
    Get disk usage. Skips virtual/read-only mounts.
    Avoids false positives on Android.
    """
    if _is_android():
        paths = [
            ("/data", "Data"),
            ("/storage/emulated/0", "Internal Storage"),
        ]
    else:
        paths = [
            ("/", "Root"),
            ("/home", "Home"),
        ]

    disks = []
    seen = set()

    for path, label in paths:
        if not os.path.exists(path):
            continue
        try:
            stat = os.statvfs(path)
            total = stat.f_blocks * stat.f_frsize
            free = stat.f_bavail * stat.f_frsize
            used = total - free

            # Skip tiny filesystems
            if total < 500 * 1024 * 1024:  # < 500 MB
                continue

            # Skip duplicates
            dev_id = (getattr(stat, 'f_fsid', 0), total)
            if dev_id in seen:
                continue
            seen.add(dev_id)

            # Skip if unreasonably 100% (virtual/read-only mount)
            if used >= total and free == 0:
                continue

            percent = round((used / total) * 100, 1) if total > 0 else 0
            disks.append({
                "device": label,
                "mount": path,
                "total_gb": round(total / (1024**3), 2),
                "used_gb": round(used / (1024**3), 2),
                "free_gb": round(free / (1024**3), 2),
                "percent": percent,
            })
        except (OSError, PermissionError):
            continue

    return disks


# ============================================================
# System load
# ============================================================

def get_system_load():
    info = {}
    if not HAS_PSUTIL:
        return info

    try:
        load = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)
        info["load_1min"] = round(load[0], 2)
        info["load_5min"] = round(load[1], 2)
        info["load_15min"] = round(load[2], 2)

        info["cpu_percent"] = _safe_psutil(
            psutil.cpu_percent, interval=0.5, default=0
        )
        info["cpu_count"] = _safe_psutil(psutil.cpu_count, default=0)

        mem = _safe_psutil(psutil.virtual_memory)
        info["memory_percent"] = mem.percent if mem else 0

        if not _is_android():
            swap = _safe_psutil(psutil.swap_memory)
            info["swap_percent"] = swap.percent if swap else 0

        boot = _safe_psutil(psutil.boot_time, default=None)
        if boot:
            info["uptime_hours"] = round(
                (datetime.now().timestamp() - boot) / 3600, 1
            )
        else:
            try:
                with open("/proc/uptime") as f:
                    info["uptime_hours"] = round(
                        float(f.read().split()[0]) / 3600, 1
                    )
            except Exception:
                info["uptime_hours"] = None
    except Exception as e:
        logger.debug(f"System load failed: {e}")

    return info


# ============================================================
# Warnings — filtered, no false positives
# ============================================================

def _analyze_warnings(data):
    warnings = []

    # --- Battery ---
    bat = data.get("battery")
    if bat:
        pct = bat.get("percentage")
        temp = bat.get("temperature")

        if pct is not None and pct < 15:
            warnings.append({
                "severity": "HIGH",
                "type": "battery_low",
                "detail": f"Battery very low: {pct}%",
            })

        # High temp threshold raised (>42°C = alert)
        if temp is not None and temp > 42:
            warnings.append({
                "severity": "HIGH" if temp > 45 else "MEDIUM",
                "type": "battery_hot",
                "detail": f"Battery warm: {temp}°C",
            })

    # --- Thermal ---
    for sensor, temp in data.get("thermal", {}).items():
        try:
            t = float(temp)
            # Only warn on real overheating
            if t > 75:
                warnings.append({
                    "severity": "HIGH",
                    "type": "thermal",
                    "detail": f"{sensor} very hot: {t}°C",
                })
            elif t > 65 and sensor != "battery":
                warnings.append({
                    "severity": "MEDIUM",
                    "type": "thermal",
                    "detail": f"{sensor} warm: {t}°C",
                })
        except (ValueError, TypeError):
            continue

    # --- CPU: only unsafe processes ---
    for p in data.get("top_processes", {}).get("cpu", [])[:5]:
        if p["cpu"] >= CPU_ALERT_THRESHOLD and not p.get("is_safe", False):
            warnings.append({
                "severity": "MEDIUM",
                "type": "high_cpu",
                "detail": f"{p['name']} (PID {p['pid']}): {p['cpu']}% CPU",
            })

    # --- Memory: only unsafe processes ---
    for p in data.get("top_processes", {}).get("memory", [])[:5]:
        if p["memory"] >= MEMORY_ALERT_THRESHOLD and not p.get("is_safe", False):
            warnings.append({
                "severity": "MEDIUM",
                "type": "high_memory",
                "detail": f"{p['name']} (PID {p['pid']}): {p['memory']}% MEM",
            })

    # --- Disk ---
    for disk in data.get("disk_usage", []):
        pct = disk["percent"]
        if pct >= DISK_CRIT_THRESHOLD:
            warnings.append({
                "severity": "HIGH",
                "type": "disk_full",
                "detail": f"{disk['mount']} {pct}% full",
            })
        elif pct >= DISK_WARN_THRESHOLD:
            warnings.append({
                "severity": "MEDIUM",
                "type": "disk_filling",
                "detail": f"{disk['mount']} {pct}% full",
            })

    return warnings


# ============================================================
# Main entry
# ============================================================

def run_resource_check():
    result = {
        "timestamp": datetime.now().isoformat(),
        "platform": platform.platform(),
        "is_android": _is_android(),
        "battery": get_battery_info(),
        "thermal": get_thermal_info(),
        "system_load": get_system_load(),
        "top_processes": get_top_processes(limit=10),
        "disk_usage": get_disk_usage(),
        "warnings": [],
        "summary": {},
    }

    result["warnings"] = _analyze_warnings(result)

    result["summary"] = {
        "cpu_percent": result["system_load"].get("cpu_percent", 0),
        "memory_percent": result["system_load"].get("memory_percent", 0),
        "battery_percent": (result["battery"] or {}).get("percentage"),
        "battery_temp": (result["battery"] or {}).get("temperature"),
        "warnings": len(result["warnings"]),
        "high_severity": sum(
            1 for w in result["warnings"] if w["severity"] == "HIGH"
        ),
    }

    return result


def print_resource_report(result):
    print("\n" + "=" * 70)
    print("  Resource Monitor Report - SentinelX")
    print("=" * 70)

    load = result.get("system_load", {})
    print(f"\n[*] CPU usage: {load.get('cpu_percent', 'N/A')}%")
    print(f"[*] Memory usage: {load.get('memory_percent', 'N/A')}%")

    uptime = load.get("uptime_hours")
    print(f"[*] Uptime: {uptime} hours" if uptime else "[*] Uptime: N/A")

    bat = result.get("battery")
    if bat:
        print(f"\n[🔋] Battery:")
        print(f"    Percentage: {bat.get('percentage')}%")
        print(f"    Status:     {bat.get('status')}")
        print(f"    Health:     {bat.get('health')}")
        print(f"    Temp:       {bat.get('temperature')}°C")

    thermal = result.get("thermal", {})
    if thermal:
        print(f"\n[🌡️] Thermal sensors:")
        for sensor, temp in thermal.items():
            try:
                t = float(temp)
                marker = "🔴" if t > 75 else "🟡" if t > 65 else "🟢"
            except (ValueError, TypeError):
                marker = "⚪"
            print(f"    {marker} {sensor}: {temp}°C")

    top_cpu = result.get("top_processes", {}).get("cpu", [])
    if top_cpu:
        print(f"\n[⚙️] Top CPU processes (filtered):")
        for p in top_cpu[:5]:
            marker = "🟡" if (p["cpu"] > CPU_ALERT_THRESHOLD and
                              not p.get("is_safe")) else "  "
            print(f"    {marker} {p['name']:<25} {p['cpu']:>6}% ({p['user']})")

    top_mem = result.get("top_processes", {}).get("memory", [])
    if top_mem:
        print(f"\n[💾] Top Memory processes (filtered):")
        for p in top_mem[:5]:
            marker = "🟡" if (p["memory"] > MEMORY_ALERT_THRESHOLD and
                              not p.get("is_safe")) else "  "
            print(f"    {marker} {p['name']:<25} {p['memory']:>6}% ({p['user']})")

    disks = result.get("disk_usage", [])
    if disks:
        print(f"\n[💿] Disk usage:")
        for d in disks:
            marker = "🔴" if d["percent"] >= DISK_CRIT_THRESHOLD else \
                     "🟡" if d["percent"] >= DISK_WARN_THRESHOLD else "🟢"
            print(f"    {marker} {d['mount']:<22} "
                  f"{d['used_gb']}/{d['total_gb']} GB ({d['percent']}%)")

    warnings = result.get("warnings", [])
    if warnings:
        print(f"\n[!] Warnings ({len(warnings)}):")
        for w in warnings:
            marker = "🔴" if w["severity"] == "HIGH" else "🟡"
            print(f"    {marker} [{w['severity']}] {w['detail']}")
    else:
        print(f"\n[✓] No resource warnings")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    r = run_resource_check()
    print_resource_report(r)
