#!/usr/bin/env python3
"""Starts fake_smtp.py and server.py, then checks the verdicts end to end."""
import json, os, subprocess, sys, time, urllib.request, urllib.parse
here = os.path.dirname(os.path.abspath(__file__))
env = dict(os.environ, PORT="8099", SMTP_PORT="2525", ALLOW_PRIVATE="1", GREYLIST_WAIT="1", HELO_HOST="probe.test", RATE_PER_MIN="1000",
           MX_OVERRIDE=",".join(d + "=127.0.0.1" for d in ["good.test", "catchall.test", "grey.test", "blocked.test", "gmial.com", "gmail.com", "down.test"]))
env["MX_OVERRIDE"] = env["MX_OVERRIDE"].replace("down.test=127.0.0.1", "down.test=127.0.0.2")
procs = [subprocess.Popen([sys.executable, os.path.join(here, "fake_smtp.py"), "2525"]),
         subprocess.Popen([sys.executable, os.path.join(here, "server.py")], env=env)]
time.sleep(1.5)

def get(path):
    try:
        with urllib.request.urlopen("http://127.0.0.1:8099" + path, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)

cases = [
    ("alice@good.test", "deliverable", "mailbox_exists"),
    ("nobody.real@good.test", "invalid", "no_mailbox"),
    ("smith.bob@good.test", "invalid", "no_mailbox"),      # recovery should suggest bob.smith@
    ("anyone@catchall.test", "risky", "catch_all"),
    ("alice@grey.test", "deliverable", "mailbox_exists"),  # greylisted once, then accepted
    ("x@blocked.test", "unknown", "unknown"),
    ("alice@gmial.com", "invalid", "no_mailbox"),          # typo; recovery should suggest alice@gmail.com
    ("a@down.test", "unknown", "unknown"),
    ("spamtrap@good.test", "invalid", "no_mailbox"),
    ("a@thisdomaindoesnotexist-98765.com", "invalid", "no_domain"),
]
bad = 0
try:
    for email, verdict, state in cases:
        code, r = get("/verify?email=" + urllib.parse.quote(email))
        ok = code == 200 and r["verdict"] == verdict and r["state"] == state
        bad += not ok
        print("OK  " if ok else "FAIL", email, "->", r.get("verdict"), r.get("state"), "recovered=%s trap=%s" % (r.get("recovered"), r.get("trap_risk")))
    code, r = get("/verify?email=notanemail"); ok = code == 400; bad += not ok; print("OK  " if ok else "FAIL", "bad format ->", code)
    code, r = get("/health"); ok = code == 200; bad += not ok; print("OK  " if ok else "FAIL", "health ->", code)
    r = get("/verify?email=smith.bob@good.test")[1]; ok = r["recovered"] == ["bob.smith@good.test"]; bad += not ok; print("OK  " if ok else "FAIL", "recovery name pattern ->", r["recovered"])
    r = get("/verify?email=alice@gmial.com")[1]; ok = r["recovered"] == ["alice@gmail.com"]; bad += not ok; print("OK  " if ok else "FAIL", "recovery typo ->", r["recovered"])
    r = get("/verify?email=spamtrap@good.test")[1]; ok = r["trap_risk"] is True; bad += not ok; print("OK  " if ok else "FAIL", "trap flag ->", r["trap_risk"])
finally:
    for p in procs: p.terminate()
print("FAILURES:", bad)
sys.exit(1 if bad else 0)
