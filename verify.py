# -*- coding: utf-8 -*-
"""Verify the annulus-proof ledger. Python 3.6+, standard library only.

  python3 verify.py chain                         # every day: hash chain + ed25519 signature (+ OTS / RFC 3161 if tools exist)
  python3 verify.py file FILE DISCLOSURE.json     # one disclosed file: salt + Merkle path -> day_root of that date

Rules (see README):
  leaf     = SHA-256(salt || file bytes)
  node     = SHA-256(left || right); leaves sorted; an odd node is carried up unchanged; empty day: SHA-256("")
  day_hash = SHA-256(prev_day_hash || day_root || "YYYY-MM-DD"); first day's prev = 32 zero bytes
  signature: `ssh-keygen -Y sign -n annulus-proof` over the 64-char lowercase hex day_hash (no newline)
  .ots / .tsr: timestamps over that same 64-char text
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROOFS = os.path.join(HERE, "proofs")
ZERO = "00" * 32


def sha(b):
    return hashlib.sha256(b).digest()


def load(day):
    with open(os.path.join(PROOFS, day + ".json"), encoding="utf-8") as f:
        return json.load(f)


def check_sig(rec, tmp):
    if not shutil.which("ssh-keygen"):
        return "skipped (no ssh-keygen)"
    msg, sig = os.path.join(tmp, "m"), os.path.join(tmp, "m.sig")
    with open(msg, "w") as f:
        f.write(rec["day_hash"])
    with open(sig, "w") as f:
        f.write(rec["signature"])
    with open(msg, "rb") as f:
        r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", os.path.join(HERE, "allowed_signers"),
                            "-I", "annulus-proof", "-n", "annulus-proof", "-s", sig], stdin=f,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return "ok" if r.returncode == 0 else "FAIL " + r.stdout.decode()[:200]


def check_ots(rec, tmp):
    p = os.path.join(PROOFS, rec["date"] + ".ots")
    if not os.path.exists(p):
        return "missing"
    if not shutil.which("ots"):
        return "present (install opentimestamps-client and run `ots verify` to check)"
    msg = os.path.join(tmp, "day_hash")
    with open(msg, "w") as f:
        f.write(rec["day_hash"])
    r = subprocess.run(["ots", "verify", "-f", msg, p], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = r.stdout.decode()
    if r.returncode == 0:
        return "ok: " + " ".join(out.split())[-120:]
    if "Pending" in out:
        return "pending Bitcoin confirmation (normal for a few hours; the owner runs `ots upgrade` daily)"
    return "FAIL: " + " ".join(out.split())[:160]


def check_tsr(rec, tmp):
    p = os.path.join(PROOFS, rec["date"] + ".tsr")
    if not os.path.exists(p):
        return "missing"
    if not shutil.which("openssl"):
        return "present (no openssl)"
    msg = os.path.join(tmp, "day_hash")
    with open(msg, "w") as f:
        f.write(rec["day_hash"])
    r = subprocess.run(["openssl", "ts", "-verify", "-data", msg, "-in", p,
                        "-CAfile", os.path.join(HERE, "tsa", "cacert.pem"),
                        "-untrusted", os.path.join(HERE, "tsa", "tsa.crt")],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if r.returncode != 0:
        return "FAIL " + r.stdout.decode()[:160]
    t = subprocess.run(["openssl", "ts", "-reply", "-in", p, "-text"], stdout=subprocess.PIPE).stdout.decode()
    when = next((l.split(":", 1)[1].strip() for l in t.splitlines() if l.startswith("Time stamp:")), "?")
    return "ok, " + when


def chain():
    days = sorted(f[:-5] for f in os.listdir(PROOFS) if f.endswith(".json"))
    prev, ok = ZERO, True
    tmp = tempfile.mkdtemp()
    import datetime as dt
    for i, d in enumerate(days):
        rec = load(d)
        if i and dt.date.fromisoformat(d) != dt.date.fromisoformat(days[i - 1]) + dt.timedelta(days=1):
            print(d, "GAP before this day")
            ok = False
        h = sha(bytes.fromhex(prev) + bytes.fromhex(rec["day_root"]) + d.encode("ascii")).hex()
        link = rec["prev"] == prev and rec["day_hash"] == h and rec["date"] == d
        ok &= link
        sig = check_sig(rec, tmp)
        ok &= not sig.startswith("FAIL")
        print("%s  chain=%s  sig=%s\n            ots=%s\n            tsr=%s"
              % (d, "ok" if link else "FAIL", sig, check_ots(rec, tmp), check_tsr(rec, tmp)))
        prev = rec["day_hash"]
    shutil.rmtree(tmp)
    print("chain OK" if ok else "CHAIN BROKEN")
    return ok


def file_(path, disclosure):
    with open(disclosure, encoding="utf-8") as f:
        d = json.load(f)
    with open(path, "rb") as f:
        node = sha(bytes.fromhex(d["salt"]) + f.read())
    for step in d["path"]:
        s = bytes.fromhex(step["hash"])
        node = sha(s + node) if step["side"] == "L" else sha(node + s)
    rec = load(d["date"])
    ok = node.hex() == rec["day_root"]
    print("file -> day_root of %s: %s" % (d["date"], "MATCH" if ok else "NO MATCH"))
    print("now run `python3 verify.py chain` to check that day's hash, signature and timestamps")
    return ok


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["chain"]:
        sys.exit(0 if chain() else 1)
    if a[:1] == ["file"] and len(a) == 3:
        sys.exit(0 if file_(a[1], a[2]) else 1)
    print(__doc__)
    sys.exit(2)
