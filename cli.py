#!/usr/bin/env python3
"""
SentinelX CLI entry point.
Allows running as: sentinelx --triage-all
"""

import sys
import os
from pathlib import Path


def main():
    """Entry point for `sentinelx` command."""
    # Get the directory where this file lives
    package_dir = Path(__file__).parent.resolve()

    # Ensure it's on path
    if str(package_dir) not in sys.path:
        sys.path.insert(0, str(package_dir))

    # Import and run SentinelX.py's main
    try:
        # Import as module
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "sentinelx_main",
            package_dir / "SentinelX.py"
        )
        sentinelx_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sentinelx_module)
        sentinelx_module.main()

    except FileNotFoundError:
        print(f"[!] SentinelX.py not found in {package_dir}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Failed to start SentinelX: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
