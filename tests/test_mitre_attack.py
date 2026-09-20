"""Tests for mitre_attack module."""

import pytest


def test_map_indicator():
    from modules.mitre_attack import map_indicator
    tid, name = map_indicator("reverse_shell")
    assert tid is not None
    assert "T1059" in tid


def test_map_unknown():
    from modules.mitre_attack import map_indicator
    tid, name = map_indicator("totally_unknown_thing")
    assert tid is None


def test_enrich_finding():
    from modules.mitre_attack import enrich_finding
    finding = {"type": "crypto_miner"}
    enriched = enrich_finding(finding)
    assert "mitre_id" in enriched
    assert enriched["mitre_id"] == "T1496"


def test_get_all_techniques():
    from modules.mitre_attack import get_all_techniques
    techniques = get_all_techniques()
    assert len(techniques) > 20
