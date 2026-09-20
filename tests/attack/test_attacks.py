"""Attack suite: adversary-perspective tests (new protocol).

Each test plays the attacker: screenshots, copied credentials, forged keys,
tampered bundles, brute force. Every one must fail against the system.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import issuer.app as issuer_app
import issuer.repo as issuer_repo
import verifier.app as verifier_app
import verifier.repo as verifier_repo
from tests.helpers import (
    enroll_holder, fresh_challenge, make_proof, p256_key, pair_shop,
)


def _setup(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_TOKEN", "admin-secret")
    base = str(tmp_path)
    issuer_app.DB = os.path.join(base, "i.db")
    issuer_app.KEYDIR = os.path.join(base, "keys")
    verifier_app.DB = os.path.join(base, "v.db")
    verifier_app.TRUST = os.path.join(base, "trust.json")
    verifier_app.SECRETS_PATH = os.path.join(base, "secrets.json")
    issuer_repo.init_db(issuer_app.DB)
    issuer_repo.seed_users(issuer_app.DB)
    verifier_repo.init_db(verifier_app.DB)
    hdr = {"Authorization": "Bearer admin-secret"}
    return issuer_app.app.test_client(), verifier_app.app.test_client(), hdr


def test_screenshot_replay_fails(tmp_path, monkeypatch):
    """Attacker screenshots the live {credential, proof} QR and replays it."""
    ic, vc, hdr = _setup(monkeypatch, tmp_path)
    pair_shop(ic, vc, hdr)
    cred, key, _ = enroll_holder(ic, hdr)
    ch = fresh_challenge(vc)
    stolen = {"c": cred, "p": make_proof(key, cred, ch["n"])}
    assert vc.post("/verify", json=stolen).get_json()["result"] == "YES"
    replayed = vc.post("/verify", json=dict(stolen)).get_json()
    assert replayed["result"] == "NO"
    assert replayed["reason"] == "UNKNOWN_CHALLENGE"


def test_copied_credential_to_another_phone(tmp_path, monkeypatch):
    """Attacker copies ONLY the credential to a second phone (no holder key).
    Without the victim's per-shop private key no valid proof can be built."""
    ic, vc, hdr = _setup(monkeypatch, tmp_path)
    pair_shop(ic, vc, hdr)
    cred, _victim_key, _ = enroll_holder(ic, hdr)
    ch = fresh_challenge(vc)
    attacker_proof = make_proof(p256_key(), cred, ch["n"])
    res = vc.post("/verify", json={"c": cred, "p": attacker_proof}).get_json()
    assert (res["result"], res["reason"]) == ("NO", "BAD_PROOF")


def test_minor_with_adults_credential(tmp_path, monkeypatch):
    """Minor holds the adult's full credential blob but a different holder key:
    proof/credential key binding (cnf) stops the swap."""
    ic, vc, hdr = _setup(monkeypatch, tmp_path)
    pair_shop(ic, vc, hdr)
    adult_cred, adult_key, _ = enroll_holder(ic, hdr, uid="U001")
    _minor_cred, minor_key, _ = enroll_holder(ic, hdr, uid="U002")
    ch = fresh_challenge(vc)
    # minor submits the ADULT credential with a proof from the MINOR's key
    res = vc.post("/verify",
                  json={"c": adult_cred,
                        "p": make_proof(minor_key, adult_cred, ch["n"])}).get_json()
    assert (res["result"], res["reason"]) == ("NO", "BAD_PROOF")
    # ...and replaying the adult's own live presentation also fails (consumed)
    ch2 = fresh_challenge(vc)
    live = {"c": adult_cred, "p": make_proof(adult_key, adult_cred, ch2["n"])}
    assert vc.post("/verify", json=live).get_json()["result"] == "YES"
    assert vc.post("/verify", json=live).get_json()["reason"] == "UNKNOWN_CHALLENGE"


def test_verifier_with_tampered_bundle(tmp_path, monkeypatch):
    """Attacker intercepts the bundle, edits the revoked list, replays it."""
    ic, vc, hdr = _setup(monkeypatch, tmp_path)
    pair_shop(ic, vc, hdr)
    bundle = ic.get("/bundle?vid=SHOP-A").get_json()
    tampered = dict(bundle, revoked=["00" * 16])
    res = vc.post("/sync", json=tampered, headers=hdr).get_json()
    assert res.get("error") == "BADSIG"


def test_brute_force_rate_limited(tmp_path, monkeypatch):
    """65 rapid OTP guesses: the limiter must start refusing with 429."""
    ic, vc, hdr = _setup(monkeypatch, tmp_path)
    pair_shop(ic, vc, hdr)
    statuses = [vc.post("/verify_code", json={"code": "000000"}).status_code
                for _ in range(65)]
    assert 429 in statuses
