"""PrefixStrip WSGI shim tests — dual hosting root + subpath."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.wsgi import PrefixStrip


def run(prefixes, path):
    seen = {}

    def inner(environ, start):
        seen["path"] = environ["PATH_INFO"]
        seen["script"] = environ.get("SCRIPT_NAME", "")
        return ["ok"]
    PrefixStrip(inner, prefixes)({"PATH_INFO": path, "SCRIPT_NAME": ""},
                                 lambda *a: None)
    return seen


def test_strips_prefix():
    assert run(["/issuer"], "/issuer/healthz") == {"path": "/healthz", "script": "/issuer"}


def test_exact_prefix_to_root():
    assert run(["/issuer"], "/issuer") == {"path": "/", "script": "/issuer"}


def test_passthrough():
    assert run(["/issuer"], "/healthz") == {"path": "/healthz", "script": ""}
    assert run(["/verifier"], "/holder/") == {"path": "/holder/", "script": ""}


def test_prefix_boundary():
    # /issuers must NOT match /issuer
    assert run(["/issuer"], "/issuers/x") == {"path": "/issuers/x", "script": ""}


def test_first_match_wins():
    assert run(["/a", "/b"], "/b/x") == {"path": "/x", "script": "/b"}
