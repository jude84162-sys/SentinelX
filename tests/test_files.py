"""Tests for files module."""

import pytest


def test_run_file_triage():
    from modules.files import run_file_triage
    result = run_file_triage()

    assert isinstance(result, dict)
    assert "summary" in result
    assert "files_scanned" in result["summary"]


def test_eicar_detection(eicar_file):
    from modules.files import _check_eicar, _get_file_info
    info = _get_file_info(eicar_file)

    if info:
        assert _check_eicar(str(eicar_file), info["size"])


def test_suspicious_filename():
    from modules.files import _is_suspicious_file
    info = {
        "path": "/tmp/payload.exe",
        "name": "payload.exe",
        "extension": ".exe",
        "size": 1000,
        "size_human": "1.0 KB",
        "age_days": 1,
    }
    is_sus, reason = _is_suspicious_file(info)
    assert is_sus
