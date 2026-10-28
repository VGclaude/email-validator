#!/usr/bin/env python3
"""A pretend mail server for testing server.py. Never sends or stores mail."""
import socketserver, sys, threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 2525
seen = {}
lock = threading.Lock()
GOOD = {"alice.jones@gmail.com", "alice@good.test", "bob.smith@good.test", "alice@gmail.com", "alice@grey.test"}


def rcpt(addr):
    a = addr.lower()
    dom = a.split("@")[-1]
    if dom == "blocked.test":
        return "554 5.7.1 Service unavailable; client host blocked by spamhaus"
    if dom in ("catchall.test", "github.com"):
        return "250 2.1.5 OK"
    if dom == "grey.test":
        with lock:
            n = seen.get(a, 0)
            seen[a] = n + 1
        if a in GOOD:
            return "451 4.7.1 Greylisted, try again later" if n == 0 else "250 2.1.5 OK"
        return "550 5.1.1 User unknown"
    return "250 2.1.5 OK" if a in GOOD else "550 5.1.1 <%s>: Recipient address rejected: User unknown" % addr


class H(socketserver.StreamRequestHandler):
    def reply(self, s):
        self.wfile.write((s + "\r\n").encode())

    def handle(self):
        self.reply("220 fake.test ESMTP")
        for raw in self.rfile:
            line = raw.decode().strip()
            cmd = line.upper()
            if cmd.startswith("EHLO"):
                self.reply("250-fake.test"); self.reply("250 8BITMIME")
            elif cmd.startswith("HELO"):
                self.reply("250 fake.test")
            elif cmd.startswith("MAIL"):
                self.reply("250 2.1.0 OK")
            elif cmd.startswith("RCPT"):
                self.reply(rcpt(line[line.index("<") + 1:line.index(">")]))
            elif cmd.startswith("RSET"):
                self.reply("250 2.0.0 OK")
            elif cmd.startswith("QUIT"):
                self.reply("221 bye"); return
            else:
                self.reply("502 not implemented")


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


S(("127.0.0.1", PORT), H).serve_forever()
