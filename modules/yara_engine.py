# modules/yara_engine.py
"""
SentinelX - YARA Engine
Advanced malware detection using YARA rules.

Features:
- 10+ built-in rules (ransomware, RAT, miner, webshell, etc.)
- Custom rules from yara_rules/ directory
- Fast scanning (compile once, scan many)
- Works on all platforms
"""

import os
import logging
from pathlib import Path

logger = logging.getLogger("SentinelX.yara")

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    logger.warning("yara-python not installed. Run: pip install yara-python")

BASE_DIR = Path(__file__).parent.parent
RULES_DIR = BASE_DIR / "yara_rules"
RULES_DIR.mkdir(exist_ok=True)


# ============================================================
# Built-in YARA rules
# ============================================================

BUILTIN_RULES = r"""
rule EICAR_Test
{
    meta:
        description = "EICAR antivirus test file"
        author = "SentinelX"
        severity = "low"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule Reverse_Shell_Linux
{
    meta:
        description = "Linux reverse shell"
        severity = "high"
    strings:
        $nc1 = "nc -e /bin/bash"
        $nc2 = "nc -e /bin/sh"
        $bash1 = "bash -i >& /dev/tcp/"
        $bash2 = "bash -i >&/dev/tcp/"
        $sh1 = "/bin/sh -i"
        $py1 = "import socket" nocase
        $perl1 = "perl -e 'use Socket"
    condition:
        any of them
}

rule Reverse_Shell_Windows
{
    meta:
        description = "Windows reverse shell"
        severity = "high"
    strings:
        $ps1 = "IEX(New-Object Net.WebClient)" nocase
        $ps2 = "Invoke-Expression" nocase
        $ps3 = "DownloadString" nocase
        $nc = "nc.exe -e cmd.exe" nocase
        $pl = "powershell -nop -w hidden" nocase
    condition:
        any of them
}

rule Web_Shell_PHP
{
    meta:
        description = "PHP web shell"
        severity = "high"
    strings:
        $eval1 = "eval(base64_decode" nocase
        $eval2 = "eval(gzinflate" nocase
        $eval3 = "eval(gzuncompress" nocase
        $eval4 = "eval(str_rot13" nocase
        $assert1 = "assert($_POST" nocase
        $assert2 = "assert($_GET" nocase
        $system1 = "system($_GET" nocase
        $system2 = "system($_POST" nocase
        $shell1 = "shell_exec($_POST" nocase
        $pass1 = "passthru($_POST" nocase
        $preg = "preg_replace('/.*/e'" nocase
    condition:
        2 of them
}

rule Ransomware_Indicators
{
    meta:
        description = "Ransomware behavior indicators"
        severity = "critical"
    strings:
        $r1 = "Your files have been encrypted" nocase
        $r2 = "Send Bitcoin to" nocase
        $r3 = "Tor Browser" nocase
        $r4 = "decrypt_instructions" nocase
        $r5 = "README_DECRYPT" nocase
        $crypto1 = "AES-256" nocase
        $crypto2 = "RSA-2048" nocase
    condition:
        2 of ($r*) or any of ($crypto*)
}

rule Crypto_Miner
{
    meta:
        description = "Cryptocurrency miner"
        severity = "medium"
    strings:
        $stratum = "stratum+tcp://" nocase
        $stratum2 = "stratum+ssl://" nocase
        $xmrig = "xmrig" nocase
        $monero1 = "moneroocean" nocase
        $monero2 = "minergate" nocase
        $pool1 = "nanopool" nocase
        $pool2 = "minexmr" nocase
        $wallet = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/
    condition:
        any of them
}

rule Keylogger_Indicators
{
    meta:
        description = "Keylogger behavior"
        severity = "high"
    strings:
        $kl1 = "SetWindowsHookEx" nocase
        $kl2 = "GetAsyncKeyState" nocase
        $kl3 = "GetKeyState" nocase
        $file1 = "keylog.txt" nocase
        $file2 = "keys.log" nocase
        $file3 = "keyboard_log" nocase
    condition:
        2 of them
}

rule Backdoor_Indicators
{
    meta:
        description = "Backdoor / RAT indicators"
        severity = "critical"
    strings:
        $r1 = "backdoor" nocase
        $r2 = "meterpreter" nocase
        $r3 = "Meterpreter" nocase
        $r4 = "shellcode" nocase
        $r5 = "payload.bin" nocase
        $r6 = "bind_shell" nocase
        $r7 = "reverse_tcp" nocase
    condition:
        2 of them
}

rule PowerShell_Obfuscation
{
    meta:
        description = "Obfuscated PowerShell"
        severity = "high"
    strings:
        $ps1 = "-EncodedCommand" nocase
        $ps2 = "-enc " nocase
        $ps3 = "[Convert]::FromBase64String" nocase
        $ps4 = "-ExecutionPolicy Bypass" nocase
        $ps5 = "-NoProfile -WindowStyle Hidden" nocase
        $chr = "chr(" nocase
        $concat = /["'][a-zA-Z]+["']\s*\+\s*["'][a-zA-Z]+["']/
    condition:
        any of ($ps*) or 2 of ($chr, $concat)
}

rule Android_Malware
{
    meta:
        description = "Android malware indicators"
        severity = "high"
    strings:
        $perm1 = "SEND_SMS"
        $perm2 = "READ_SMS"
        $perm3 = "RECEIVE_SMS"
        $perm4 = "PROCESS_OUTGOING_CALLS"
        $perm5 = "READ_CALL_LOG"
        $suspicious1 = "sendSms" nocase
        $suspicious2 = "TelephonyManager" nocase
        $suspicious3 = "getDeviceId" nocase
        $suspicious4 = "getSubscriberId" nocase
    condition:
        3 of them
}

rule Crypto_Wallet_Stealer
{
    meta:
        description = "Crypto wallet stealer"
        severity = "critical"
    strings:
        $wallet1 = "wallet.dat" nocase
        $wallet2 = "Electrum" nocase
        $wallet3 = "Metamask" nocase
        $wallet4 = "bitcoin" nocase
        $wallet5 = "ethereum" nocase
        $steal = "stealer" nocase
    condition:
        (2 of ($wallet*)) and $steal
}
"""


# ============================================================
# Compile helpers
# ============================================================

_compiled_builtin = None
_compiled_custom = None
_custom_mtime = 0


def _compile_builtin():
    """Compile built-in rules (once)."""
    global _compiled_builtin
    if not HAS_YARA:
        return None
    if _compiled_builtin is None:
        try:
            _compiled_builtin = yara.compile(source=BUILTIN_RULES)
            logger.info("Built-in YARA rules compiled")
        except yara.SyntaxError as e:
            logger.error(f"Built-in YARA syntax error: {e}")
            return None
    return _compiled_builtin


def _compile_custom():
    """Compile custom rules from yara_rules/ dir."""
    global _compiled_custom, _custom_mtime
    if not HAS_YARA:
        return None

    # Check for changes
    rule_files = list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara"))
    if not rule_files:
        return None

    latest_mtime = max(f.stat().st_mtime for f in rule_files)
    if _compiled_custom is not None and latest_mtime == _custom_mtime:
        return _compiled_custom

    # Compile all
    sources = {}
    for f in rule_files:
        sources[f.stem] = str(f)

    try:
        _compiled_custom = yara.compile(filepaths=sources)
        _custom_mtime = latest_mtime
        logger.info(f"Custom YARA rules compiled ({len(sources)} files)")
        return _compiled_custom
    except yara.SyntaxError as e:
        logger.error(f"Custom YARA syntax error: {e}")
        return None


def _all_rules():
    """Get all compiled rules."""
    rules = []
    builtin = _compile_builtin()
    if builtin:
        rules.append(("builtin", builtin))
    custom = _compile_custom()
    if custom:
        rules.append(("custom", custom))
    return rules


# ============================================================
# Scanning
# ============================================================

def scan_file(filepath, rules=None):
    """Scan a single file."""
    if not HAS_YARA:
        return []

    if rules is None:
        rules = _all_rules()

    if not rules:
        return []

    matches = []
    for source, r in rules:
        try:
            for m in r.match(filepath):
                matches.append({
                    "path": filepath,
                    "rule": m.rule,
                    "source": source,
                    "severity": m.meta.get("severity", "unknown"),
                    "description": m.meta.get("description", ""),
                    "tags": list(m.tags),
                })
        except yara.Error as e:
            logger.debug(f"YARA scan failed for {filepath}: {e}")
        except (PermissionError, OSError):
            pass

    return matches


def scan_directory(target_dir, max_size=50 * 1024 * 1024,
                   max_files=5000, skip_dirs=None):
    """Scan directory with YARA."""
    if not HAS_YARA:
        return {
            "error": "yara-python not installed. Run: pip install yara-python",
            "matches": [],
        }

    if skip_dirs is None:
        skip_dirs = {"__pycache__", "node_modules", ".git", ".cache",
                     "venv", ".venv", "go", ".cargo", ".rustup"}

    rules = _all_rules()
    if not rules:
        return {"error": "No YARA rules available", "matches": []}

    results = {
        "target": target_dir,
        "scanned": 0,
        "skipped": 0,
        "matches": [],
    }

    files_scanned = 0
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for fname in files:
            if files_scanned >= max_files:
                break

            filepath = os.path.join(root, fname)

            try:
                if os.path.getsize(filepath) > max_size:
                    results["skipped"] += 1
                    continue
            except OSError:
                continue

            files_scanned += 1
            results["scanned"] += 1

            for source, r in rules:
                try:
                    for m in r.match(filepath):
                        results["matches"].append({
                            "path": filepath,
                            "rule": m.rule,
                            "source": source,
                            "severity": m.meta.get("severity", "unknown"),
                            "description": m.meta.get("description", ""),
                        })
                except Exception:
                    continue

        if files_scanned >= max_files:
            break

    return results


def print_yara_report(result):
    print("\n" + "=" * 70)
    print("  YARA Engine Report - SentinelX")
    print("=" * 70)

    if result.get("error"):
        print(f"\n[!] {result['error']}")
        return

    print(f"\n[*] Target: {result.get('target')}")
    print(f"[*] Files scanned: {result.get('scanned', 0)}")
    print(f"[*] Files skipped: {result.get('skipped', 0)}")
    print(f"[*] Matches: {len(result.get('matches', []))}")

    matches = result.get("matches", [])
    if matches:
        # Group by severity
        by_sev = {}
        for m in matches:
            sev = m.get("severity", "unknown")
            by_sev.setdefault(sev, []).append(m)

        for sev in ("critical", "high", "medium", "low", "unknown"):
            if sev not in by_sev:
                continue
            marker = {"critical": "🔴", "high": "🔴",
                      "medium": "🟡", "low": "🔵"}.get(sev, "⚪")
            print(f"\n[!] {marker} {sev.upper()} ({len(by_sev[sev])}):")
            for m in by_sev[sev][:10]:
                print(f"    {marker} {m['path']}")
                print(f"       Rule: {m['rule']}")
                print(f"       {m['description']}")
    else:
        print(f"\n[✓] No YARA matches")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if not HAS_YARA:
        print("[!] yara-python not installed.")
        print("    Run: pip install yara-python")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.yara_engine <path>")
        sys.exit(1)

    target = os.path.expanduser(sys.argv[1])
    if not os.path.exists(target):
        print(f"Error: {target} not found")
        sys.exit(1)

    if os.path.isfile(target):
        matches = scan_file(target)
        result = {"target": target, "scanned": 1, "matches": matches}
    else:
        result = scan_directory(target)

    print_yara_report(result)
