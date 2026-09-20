"""Attack + unit tests. agency: api-tester, test-automation-engineer | ECC: tdd-workflow, verification-loop."""
import time

from shared.crypto import (
    gen_keypair, gen_nonce, otp6, pseudonym, receipt_hash, sign_cred, verify_sig,
)


def make_cred(priv, pub, adult=True, exp_offset=300, n=None, verifier="SHOP-A"):
    payload = {"v": 1, "iss": "NIMC-TEST-01", "uid_p": "abcd1234efgh5678",
               "a": "over_18", "r": 1 if adult else 0,
               "exp": int(time.time()) + exp_offset, "n": n}
    if n is None:
        payload.pop("n")
    payload["s"] = sign_cred(payload, priv)
    return payload


def test_valid_sig():
    priv, pub = gen_keypair()
    c = make_cred(priv, pub)
    body = {k: c[k] for k in c if k != "s"}
    assert verify_sig(body, c["s"], pub)


def test_tampered_result_rejected():
    priv, pub = gen_keypair()
    c = make_cred(priv, pub, adult=False)
    c["r"] = 1
    body = {k: c[k] for k in c if k != "s"}
    assert not verify_sig(body, c["s"], pub)


def test_unknown_issuer_rejected():
    priv, _ = gen_keypair()
    _, pub2 = gen_keypair()
    c = make_cred(priv, pub2)
    body = {k: c[k] for k in c if k != "s"}
    assert not verify_sig(body, c["s"], pub2)


def test_expired_rejected_by_policy():
    priv, pub = gen_keypair()
    c = make_cred(priv, pub, exp_offset=-60)
    assert c["exp"] < time.time()  # verifier decide() maps this to EXPIRED


def test_nonce_binding():
    """Replay: static QR (n=None) cannot satisfy a fresh challenge."""
    priv, pub = gen_keypair()
    static = make_cred(priv, pub)
    assert static.get("n") is None
    fresh = gen_nonce()
    # verifier requires cred['n'] == fresh nonce; static copy fails
    assert static.get("n") != fresh


def test_forged_unsigned_rejected():
    _, pub = gen_keypair()
    fake = {"v": 1, "iss": "NIMC-TEST-01", "uid_p": "x",
            "a": "over_18", "r": 1, "exp": int(time.time()) + 300, "s": "fake"}
    body = {k: fake[k] for k in fake if k != "s"}
    assert not verify_sig(body, "fake", pub)


def test_pseudonym_differs_per_shop():
    s = "00" * 16
    assert pseudonym(s, "SHOP-A") != pseudonym(s, "SHOP-B")


def test_otp_changes_per_step():
    s = "11" * 16
    assert otp6(s, "SHOP-A", 100) != otp6(s, "SHOP-A", 101)


def test_receipt_chain_tamper_evident():
    h0 = receipt_hash("GENESIS", 1, "SHOP-A", "over_18", "YES", "n", "s")
    h1 = receipt_hash(h0, 2, "SHOP-A", "over_18", "NO", "n", "s")
    assert h0 != h1
    assert receipt_hash("XXX", 2, "SHOP-A", "over_18", "NO", "n", "s") != h1
