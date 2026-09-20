"""Scripts + deployment: seed, receipt auditor, demo, run.sh, blueprint."""
import os
import socket
import subprocess
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

REPO = os.path.join(os.path.dirname(__file__), "..", "..")


def test_seed_idempotent(tmp_path):
    sys.path.insert(0, os.path.join(REPO, "scripts"))
    import seed as seed_mod
    _ = seed_mod  # imports cleanly; exercised via issuer.repo below
    db = os.path.join(str(tmp_path), "seed.db")
    import issuer.repo as repo

    repo.init_db(db)
    assert repo.seed_users(db) == 4
    assert repo.seed_users(db) == 0  # second run inserts nothing
    conn = repo.connect(db)
    ids = sorted(r["id"] for r in conn.execute("SELECT id FROM users"))
    conn.close()
    assert ids == ["U001", "U002", "U003", "U004"]


def _servers(tmp_path):
    import issuer.app as issuer_app
    import issuer.repo as issuer_repo
    import verifier.app as verifier_app
    import verifier.repo as verifier_repo

    os.environ["ADMIN_TOKEN"] = "admin-secret"
    base = str(tmp_path)
    issuer_app.DB = os.path.join(base, "i.db")
    issuer_app.KEYDIR = os.path.join(base, "keys")
    verifier_app.DB = os.path.join(base, "v.db")
    verifier_app.TRUST = os.path.join(base, "t.json")
    verifier_app.SECRETS_PATH = os.path.join(base, "s.json")
    issuer_repo.init_db(issuer_app.DB)
    issuer_repo.seed_users(issuer_app.DB)
    verifier_repo.init_db(verifier_app.DB)

    def free():
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    iport, vport = free(), free()
    for target, port in ((lambda: issuer_app.app.run(port=iport, use_reloader=False), iport),
                         (lambda: verifier_app.app.run(port=vport, use_reloader=False), vport)):
        threading.Thread(target=target, daemon=True).start()
    import urllib.request
    import time as _t

    for port in (iport, vport):
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2)
                break
            except Exception:
                _t.sleep(0.1)
    return f"http://127.0.0.1:{iport}", f"http://127.0.0.1:{vport}"


def test_verify_receipts_script(tmp_path):
    sys.path.insert(0, os.path.join(REPO, "scripts"))
    import verify_receipts as vr
    import verifier.repo as verifier_repo
    import verifier.services as verifier_services

    db = os.path.join(str(tmp_path), "v.db")
    verifier_repo.init_db(db)
    key = verifier_services.load_receipt_key(db)
    verifier_repo.append_receipt(
        db, ts=1, verifier_id="S", q="over_18:proof", result="YES", reason="OK",
        entry_hash_of=lambda prev: verifier_services.chain_entry(
            prev, 1, "S", "over_18:proof", "YES", "OK", key))
    assert vr.main.__code__.co_names  # module imports cleanly
    # run via CLI entry with patched argv
    old_argv = sys.argv
    sys.argv = ["verify_receipts.py", "--db", db]
    try:
        assert vr.main() == 0
    finally:
        sys.argv = old_argv
    # tamper -> exit 1
    conn = verifier_repo.connect(db)
    conn.execute("UPDATE receipts SET result='NO' WHERE id=1")
    conn.commit()
    conn.close()
    sys.argv = ["verify_receipts.py", "--db", db]
    try:
        assert vr.main() == 1
    finally:
        sys.argv = old_argv


def test_demo_script_end_to_end(tmp_path):
    sys.path.insert(0, os.path.join(REPO, "scripts"))
    import demo as demo_mod

    issuer_url, verifier_url = _servers(tmp_path)
    env = {"ISSUER_URL": issuer_url, "VERIFIER_URL": verifier_url,
           "ADMIN_TOKEN": "admin-secret", "PATH": os.environ["PATH"]}
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO, "scripts", "demo.py")],
        capture_output=True, text=True, env={**os.environ, **env}, timeout=120,
        cwd=REPO)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for line in ("YES", "BADSIG", "replay blocked", "forged bundle rejected",
                 "rogue-key bundle rejected", "revoked after sync"):
        assert line in proc.stdout, proc.stdout
    _ = demo_mod  # module itself imports cleanly (code above exercises main via CLI)


def test_run_sh_boots_and_pairs(tmp_path):
    proc = subprocess.Popen(
        ["bash", os.path.join(REPO, "run.sh")],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        cwd=str(tmp_path),
        env={**os.environ, "ADMIN_TOKEN": "runsh-secret",
             "PY": sys.executable,
             "ISSUER_DB": os.path.join(str(tmp_path), "i.db"),
             "VERIFIER_DB": os.path.join(str(tmp_path), "v.db")})
    try:
        output = ""
        import time as _t

        deadline = _t.time() + 60
        while _t.time() < deadline:
            chunk = proc.stdout.readline() if proc.stdout else ""
            if not chunk:
                break
            output += chunk
            if "Demo enrollment code" in output:
                break
        assert "Demo enrollment code" in output, output[-2000:]
        assert "sync:" in output and "'ok': True" in output
    finally:
        proc.kill()
        try:
            proc.wait(timeout=10)
        except Exception:
            pass


def test_render_blueprint_has_disk_and_env():
    text = open(os.path.join(REPO, "deploy", "render.blueprint.yaml")).read()
    for needle in ("mountPath: /data", "sizeGB:", "ADMIN_TOKEN", "--workers 1",
                   "ISSUER_DB", "VERIFIER_DB", "OTP_SECRETS_PATH", "BEHIND_PROXY"):
        assert needle in text, needle
