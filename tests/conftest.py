"""Pytest bootstrap: safe test defaults for env-driven config.

App modules read ADMIN_TOKEN at import (refuse-to-start when unset outside
debug), so the test session pins deterministic values here. Tests that need
different env (e.g. missing token) use subprocesses or monkeypatch + reimport.
"""
import os

import pytest

os.environ.setdefault("ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault("FLASK_DEBUG", "1")


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """In-memory limiter counters persist per process: reset before every test
    so brute-force tests can't flake the rest of the suite (and vice versa)."""
    yield
    for module_name in ("issuer.app", "verifier.app"):
        module = __import__(module_name, fromlist=["x"])
        limiter = getattr(module, "limiter", None)
        storage = getattr(limiter, "_storage", None)
        reset = getattr(storage, "reset", None)
        if callable(reset):
            reset()
