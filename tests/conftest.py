# tests/conftest.py
"""Pytest fixtures for SentinelX tests."""

import os
import sys
import pytest
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def temp_file(tmp_path):
    """Create a temporary file."""
    f = tmp_path / "test.txt"
    f.write_text("test content")
    return f


@pytest.fixture
def eicar_file(tmp_path):
    """Create an EICAR test file."""
    f = tmp_path / "eicar.txt"
    f.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    return f


@pytest.fixture
def temp_dir(tmp_path):
    """Create a temporary directory with files."""
    for i in range(5):
        (tmp_path / f"file{i}.txt").write_text(f"content {i}")
    return tmp_path
