#!/usr/bin/env python3
"""Address Check verification server.

Checks whether a mailbox exists by talking SMTP to the recipient's mail server
(RCPT TO, no message is ever sent), detects catch-all domains, retries
greylisted answers, flags likely spam traps and tries to recover mistyped
addresses. Standard library only.

Needs outbound TCP port 25. Many hosts block it; see README.md.
"""
import ipaddress
import json
import os
import random
import re
import smtplib
import socket
import string
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8080"))
HELO_HOST = os.environ.get("HELO_HOST") or socket.getfqdn()
PROBE_FROM = os.environ.get("PROBE_FROM") or ("verify@" + HELO_HOST)
SMTP_PORT = int(os.environ.get("SMTP_PORT", "25"))
SMTP_TIMEOUT = float(os.environ.get("SMTP_TIMEOUT", "12"))
GREYLIST_WAIT = float(os.environ.get("GREYLIST_WAIT", "25"))
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
RATE_PER_MIN = int(os.environ.get("RATE_PER_MIN", "30"))
TRUST_PROXY = os.environ.get("TRUST_PROXY") == "1"
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE") == "1"  # tests only
MX_OVERRIDE = dict(p.split("=", 1) for p in os.environ.get("MX_OVERRIDE", "").split(",") if "=" in p)
MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT", "10"))

TYPOS = {
    "gmial.com": "gmail.com", "gmai.com": "gmail.com", "gmail.con": "gmail.com", "gmail.cm": "gmail.com", "gmail.om": "gmail.com",
    "gmail.comm": "gmail.com", "gmail.co": "gmail.com", "gmal.com": "gmail.com", "gnail.com": "gmail.com", "gamil.com": "gmail.com",
    "gmaill.com": "gmail.com", "hotmial.com": "hotmail.com", "hotmal.com": "hotmail.com", "hotmail.con": "hotmail.com",
    "hotmai.com": "hotmail.com", "yaho.com": "yahoo.com", "yahooo.com": "yahoo.com", "yahoo.con": "yahoo.com", "yhoo.com": "yahoo.com",
    "outlok.com": "outlook.com", "outllook.com": "outlook.com", "outlook.con": "outlook.com", "iclod.com": "icloud.com",
    "iclould.com": "icloud.com", "icloud.con": "icloud.com",
}
TRAP_LOCALS = {"spamtrap", "spam-trap", "honeypot", "honey-pot", "trap", "abuse-trap", "blackhole", "devnull", "dev-null", "nobody", "donotmail"}
TRAP_DOMAINS = {"spamcop.net", "spamhaus.org", "abuse.net", "spamtrap.org", "honeypot.org"}
BLOCK_HINTS = re.compile(r"spamhaus|blocklist|blacklist|block list|black list|reputation|banned|denied|policy|not allowed|access|rbl|sorbs|barracuda|poor|spam", re.I)
EMAIL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")

_mx_cache, _result_cache, _hits = {}, {}, {}
_lock = threading.Lock()
_slots = threading.BoundedSemaphore(MAX_CONCURRENT)


def doh(name, qtype):
    url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": name, "type": qtype})
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.load(r)


def lookup_mx(domain):
    """Returns (state, hosts). state: mx | nxdomain | nullmx | nomail | error."""
    if domain in MX_OVERRIDE:
        return "mx", [MX_OVERRIDE[domain]]
    now = time.time()
    hit = _mx_cache.get(domain)
    if hit and hit[0] > now:
        return hit[1], hit[2]
    try:
        d = doh(domain, "MX")
        if d.get("Status") == 3:
            out = ("nxdomain", [])
        else:
            recs = []
            for a in d.get("Answer", []):
                if a.get("type") == 15:
                    p = a["data"].split(" ")
                    recs.append((int(p[0]), (p[1] if len(p) > 1 else "").rstrip(".")))
            recs.sort()
            if recs and recs[0][1] == "" and len(recs) == 1:
                out = ("nullmx", [])
            elif recs:
                out = ("mx", [h for _, h in recs])
            elif d.get("Status") == 0:
                a4 = doh(domain, "A")
                has = any(x.get("type") == 1 for x in a4.get("Answer", []))
                out = ("mx", [domain]) if has else ("nomail", [])
            else:
                return "error", []
    except Exception as e:
        print("DNS lookup failed for %s: %s" % (domain, e), flush=True)
        return "error", []
    _mx_cache[domain] = (now + 300, out[0], out[1])
    return out


def host_is_public(host):
    if ALLOW_PRIVATE:
        return True
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_global for i in infos)


def classify(code, msg):
    text = msg.decode("utf-8", "replace") if isinstance(msg, bytes) else str(msg)
    if code in (250, 251):
        return "accepted"
    if 400 <= code < 500:
        return "temp"
    if code >= 500:
        if BLOCK_HINTS.search(text) and not re.search(r"user unknown|no such user|does not exist|unknown user|mailbox unavailable|recipient (not found|rejected)|invalid (mailbox|recipient)|no mailbox", text, re.I):
            return "blocked"
        return "rejected"
    return "unknown"


def smtp_session(hosts, addrs):
    """One connection, one RCPT TO per address. Returns (list of (state, code, text), host)."""
    last_err = "could not connect"
    for host in hosts[:3]:
        if not host_is_public(host):
            last_err = "mail server address is not public"
            continue
        s = None
        try:
            s = smtplib.SMTP(local_hostname=HELO_HOST, timeout=SMTP_TIMEOUT)
            s.connect(host, SMTP_PORT)
            s.ehlo_or_helo_if_needed()
            out = []
            for i, a in enumerate(addrs):
                if i:
                    s.rset()
                code, msg = s.mail(PROBE_FROM)
                if code >= 400:
                    out.append(("blocked", code, msg.decode("utf-8", "replace")))
                    continue
                code, msg = s.rcpt(a)
                out.append((classify(code, msg), code, msg.decode("utf-8", "replace")[:200]))
            return out, host
        except (smtplib.SMTPException, OSError) as e:
            last_err = type(e).__name__ + ": " + str(e)[:120]
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
    return [("error", 0, last_err)] * len(addrs), None


def random_local():
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(18))


def name_variants(local):
    toks = [t for t in re.split(r"[._-]+", local.lower()) if t.isalpha()]
    if len(toks) < 2:
        return []
    f, l = toks[0], toks[-1]
    out = [f + "." + l, f + l, f[0] + l, f + "_" + l, f + "-" + l, l + "." + f, f, f[0] + "." + l]
    seen, res = {local.lower()}, []
    for v in out:
        if v not in seen:
            seen.add(v)
            res.append(v)
    return res[:8]


def verify(email):
    local, domain = email.rsplit("@", 1)
    domain = domain.lower()
    res = {"email": email, "verdict": "unknown", "state": "unknown", "checks": [], "recovered": [], "trap_risk": False, "mx": []}
    add = lambda s, t: res["checks"].append({"s": s, "t": t})

    if local.lower() in TRAP_LOCALS or domain in TRAP_DOMAINS or "spamtrap" in local.lower():
        res["trap_risk"] = True
        add("warn", "Matches a pattern used by spam-trap addresses. Mailing it can damage a sender's reputation.")

    state, hosts = lookup_mx(domain)
    res["mx"] = hosts[:5]
    if state == "nxdomain":
        res.update(verdict="invalid", state="no_domain"); add("fail", "The domain does not exist."); return fixup(res, local, domain, None)
    if state in ("nullmx", "nomail"):
        res.update(verdict="invalid", state="no_mail"); add("fail", "The domain does not accept email."); return fixup(res, local, domain, None)
    if state == "error":
        add("warn", "Could not look up the domain's mail servers."); return res
    add("pass", "Mail servers found: " + ", ".join(hosts[:2]) + ".")

    probes = [email, local_catchall(domain)]
    results, host = smtp_session(hosts, probes)
    target, rnd = results
    if target[0] == "temp":
        add("warn", "Mail server asked to try again later (greylisting). Retrying in %ds." % GREYLIST_WAIT)
        time.sleep(GREYLIST_WAIT)
        results, host = smtp_session(hosts, probes)
        target, rnd = results
        if target[0] == "temp":
            add("warn", "Still deferred after one retry. Result unknown.")
    if target[0] == "error":
        add("warn", "Could not talk to the mail server (" + target[2] + "). Port 25 may be blocked.")
        return res
    if target[0] == "blocked":
        add("warn", "The mail server refused to answer the check (%s)." % target[2][:80])
        return res
    if target[0] == "rejected":
        res.update(verdict="invalid", state="no_mailbox"); add("fail", "The mail server says this mailbox does not exist (%d)." % target[1])
        return fixup(res, local, domain, hosts)
    if target[0] == "accepted":
        if rnd[0] == "accepted":
            res.update(verdict="risky", state="catch_all")
            add("warn", "The domain accepts mail for any address (catch-all), so this mailbox cannot be confirmed.")
        elif rnd[0] == "rejected":
            res.update(verdict="deliverable", state="mailbox_exists")
            add("pass", "The mail server accepted this mailbox and rejected a made-up one.")
        else:
            res.update(verdict="deliverable", state="mailbox_exists_unconfirmed")
            add("pass", "The mail server accepted this mailbox.")
            add("warn", "The catch-all test was inconclusive.")
    return res


def local_catchall(domain):
    return random_local() + "@" + domain


def fixup(res, local, domain, hosts):
    """Recovery: typo-corrected domain and name-pattern variants, each verified over SMTP."""
    cands = []
    if domain in TYPOS:
        cands.append(local + "@" + TYPOS[domain])
    elif res["state"] == "no_mailbox" and hosts:
        cands.extend(v + "@" + domain for v in name_variants(local))
    if not cands:
        return res
    if domain in TYPOS:
        state, h = lookup_mx(TYPOS[domain])
        if state == "mx":
            rs, _ = smtp_session(h, cands + [local_catchall(TYPOS[domain])])
            if rs[0][0] == "accepted" and rs[-1][0] != "accepted":
                res["recovered"].append(cands[0])
    else:
        rs, _ = smtp_session(hosts, cands + [local_catchall(domain)])
        if rs[-1][0] == "rejected":  # only trust the answers on domains that are not catch-all
            res["recovered"] = [c for c, r in zip(cands, rs) if r[0] == "accepted"]
    if res["recovered"]:
        res["checks"].append({"s": "pass", "t": "Possible correct address found: " + ", ".join(res["recovered"]) + "."})
    return res


def client_ip(h):
    if TRUST_PROXY and h.headers.get("X-Forwarded-For"):
        return h.headers["X-Forwarded-For"].split(",")[0].strip()
    return h.client_address[0]


def rate_ok(ip):
    now = time.time()
    with _lock:
        q = [t for t in _hits.get(ip, []) if now - t < 60]
        if len(q) >= RATE_PER_MIN:
            _hits[ip] = q
            return False
        q.append(now)
        _hits[ip] = q
    return True


class Handler(BaseHTTPRequestHandler):
    server_version = "AddressCheck/1.0"

    def log_message(self, fmt, *a):
        pass

    def send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/health":
            return self.send_json(200, {"ok": True})
        if u.path != "/verify":
            return self.send_json(404, {"error": "not found"})
        email = urllib.parse.parse_qs(u.query).get("email", [""])[0].strip()
        if not EMAIL_RE.match(email) or ".." in email or email.startswith(".") or "@." in email:
            return self.send_json(400, {"error": "invalid email format"})
        if not rate_ok(client_ip(self)):
            return self.send_json(429, {"error": "too many requests, try again in a minute"})
        key = email.lower()
        hit = _result_cache.get(key)
        if hit and hit[0] > time.time():
            return self.send_json(200, hit[1])
        if not _slots.acquire(timeout=30):
            return self.send_json(503, {"error": "server busy"})
        try:
            res = verify(email)
        except Exception as e:  # never leak a stack trace
            return self.send_json(500, {"error": "verification failed"})
        finally:
            _slots.release()
        if res["verdict"] != "unknown":
            _result_cache[key] = (time.time() + 600, res)
        self.send_json(200, res)


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("Address Check server on :%d, HELO %s, MAIL FROM %s" % (PORT, HELO_HOST, PROBE_FROM), flush=True)
    srv.serve_forever()
