"""Playwright smoke: holder + shop pages load, work, and survive offline.

Requires playwright + chromium (CI installs them). Skips cleanly otherwise.
Run: pytest tests/test_smoke_playwright.py
"""
import json
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pytest

import issuer.app as issuer_app
import issuer.repo as issuer_repo
import verifier.app as verifier_app
import verifier.repo as verifier_repo

playwright = pytest.importorskip("playwright.sync_api")

ADMIN_HDR = {"Authorization": "Bearer admin-secret"}


def _launch(pw):
    """Launch Chromium: playwright-bundled build first, system Chrome fallback
    (dev machines often have google-chrome but no `playwright install` cache)."""
    try:
        return pw.chromium.launch()
    except Exception as exc:
        if "Executable doesn't exist" not in str(exc):
            raise
        return pw.chromium.launch(channel="chrome")


def _free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture(scope="module")
def servers(tmp_path_factory):
    tmp = str(tmp_path_factory.mktemp("pw"))
    os.environ["ADMIN_TOKEN"] = "admin-secret"
    issuer_app.DB = os.path.join(tmp, "i.db")
    issuer_app.KEYDIR = os.path.join(tmp, "keys")
    verifier_app.DB = os.path.join(tmp, "v.db")
    verifier_app.SECRETS_PATH = os.path.join(tmp, "secrets.json")
    issuer_repo.init_db(issuer_app.DB)
    issuer_repo.seed_users(issuer_app.DB)
    verifier_repo.init_db(verifier_app.DB)
    iport, vport = _free_port(), _free_port()

    def run_issuer():
        issuer_app.app.run(port=iport, use_reloader=False)

    def run_verifier():
        verifier_app.app.run(port=vport, use_reloader=False)

    threads = [threading.Thread(target=run_issuer, daemon=True),
               threading.Thread(target=run_verifier, daemon=True)]
    for t in threads:
        t.start()
    import urllib.request

    for port in (iport, vport):
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz",
                                       timeout=2).read()
                break
            except Exception:
                import time as _t
                _t.sleep(0.1)
    yield {"issuer": f"http://127.0.0.1:{iport}",
           "verifier": f"http://127.0.0.1:{vport}"}


def _api_post(base, path, body, headers=None):
    import urllib.request

    req = urllib.request.Request(
        base + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())


def _api_get(base, path, headers=None):
    import urllib.request

    req = urllib.request.Request(base + path, headers=headers or {})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())


def test_holder_enroll_and_offline(servers):
    from playwright.sync_api import sync_playwright

    base = servers["issuer"]
    code = _api_post(base, "/admin/users/U001/enrollment-code", {},
                     ADMIN_HDR)["code"]
    with sync_playwright() as pw:
        browser = _launch(pw)
        page = browser.new_page()
        page.goto(base + "/holder/", wait_until="networkidle")
        page.click("text=Demo settings")
        page.fill("#iss", base)
        page.fill("#enrollCode", code)
        page.click("#enrollBtn")
        page.wait_for_selector("#okmsg:not(:empty)", timeout=15000)
        assert "Enrolled" in page.inner_text("#okmsg")
        # service worker precached? then go offline and reload
        page.wait_for_timeout(1500)
        page.context.set_offline(True)
        page.reload(wait_until="domcontentloaded")
        assert "My ID" in page.inner_text("h1")
        browser.close()


def test_shop_camera_denied_graceful(servers):
    from playwright.sync_api import sync_playwright

    _ibase, vbase = servers["issuer"], servers["verifier"]
    with sync_playwright() as pw:
        browser = _launch(pw)
        context = browser.new_context(permissions=[])
        page = context.new_page()
        page.goto(vbase + "/", wait_until="domcontentloaded")
        page.click("#scanBtn")
        page.wait_for_timeout(2000)
        msg = page.inner_text("#msg")
        assert "paste" in msg.lower(), msg  # graceful fallback, never alert()/blank
        browser.close()


def test_shop_paste_flow_and_offline(servers):
    from playwright.sync_api import sync_playwright

    ibase, vbase = servers["issuer"], servers["verifier"]
    bundle = _api_get(ibase, "/bundle?vid=SHOP-A")
    _api_post(vbase, "/sync", bundle, ADMIN_HDR)
    # second device key enrolled purely via API (holder private keys never leave browsers)
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.hashes import SHA256
    from shared.canonical import canonical
    from shared.crypto import b64u_encode, sha256_hex
    from shared.schemas import signed_body

    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.private_numbers().public_numbers
    pub = b64u_encode(b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big"))
    code = _api_post(ibase, "/admin/users/U001/enrollment-code", {}, ADMIN_HDR)["code"]
    cred = _api_post(ibase, "/enroll",
                     {"code": code, "verifier_id": "SHOP-A",
                      "holder_pub": pub})["credential"]
    ch = _api_get(vbase, "/challenge")
    import time as _time

    ts = int(_time.time())
    msg = canonical(["yn-proof-v1", sha256_hex(canonical(signed_body(cred))),
                     ch["n"], "SHOP-A", ts])
    r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(SHA256())))
    presentation = json.dumps({"c": cred, "p": {
        "n": ch["n"], "ts": ts,
        "sig": b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}})
    with sync_playwright() as pw:
        browser = _launch(pw)
        page = browser.new_page()
        page.goto(vbase + "/", wait_until="domcontentloaded")
        assert "Shop check" in page.inner_text("h1")
        page.fill("#credInput", presentation)
        page.click("#verifyBtn")
        page.wait_for_selector("#result.show", timeout=15000)
        assert "YES" in page.inner_text("#resultWord")
        page.context.set_offline(True)
        page.reload(wait_until="domcontentloaded")
        assert "Shop check" in page.inner_text("h1")
        browser.close()
