"""Tests for env_detect module."""

import pytest


def test_get_environment():
    from modules.env_detect import get_environment
    env = get_environment()

    assert isinstance(env, dict)
    assert "platform" in env
    assert "is_android" in env
    assert "capabilities" in env


def test_get_env_label():
    from modules.env_detect import get_environment, get_env_label
    env = get_environment()
    label = get_env_label(env)

    assert isinstance(label, str)
    assert len(label) > 0
