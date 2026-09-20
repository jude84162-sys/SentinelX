"""Tests for ioc_hunter module."""

import pytest


def test_calculate_sha256(temp_file):
    from modules.ioc_hunter import calculate_sha256
    h = calculate_sha256(str(temp_file))
    assert h is not None
    assert len(h) == 64


def test_eicar_hash(eicar_file):
    from modules.ioc_hunter import calculate_sha256
    h = calculate_sha256(str(eicar_file))
    assert h == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_load_local_iocs():
    from modules.ioc_hunter import load_local_iocs
    iocs = load_local_iocs()
    assert isinstance(iocs, dict)


def test_add_ioc():
    from modules.ioc_hunter import add_ioc, load_local_iocs
    test_hash = "0" * 64
    add_ioc(test_hash, "Test.Threat")
    iocs = load_local_iocs()
    assert test_hash in iocs
