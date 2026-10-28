# Address Check verification server

Checks whether a mailbox exists by talking SMTP to the recipient's mail server (`RCPT TO`, no message is sent).
It also detects catch-all domains, retries greylisted answers once, flags likely spam-trap addresses and
suggests corrections (typo-fixed domains and first.last name patterns, each verified over SMTP).

Standard library only. Python 3.9+.

## Requirements

- **Outbound TCP port 25 open.** Home internet and many clouds block it (AWS, Google Cloud, Azure, DigitalOcean,
  Vultr and others block it by default or on new accounts). Test first: `nc -vz gmail-smtp-in.l.google.com 25`.
- A public hostname with **reverse DNS (PTR)** matching `HELO_HOST`. Many servers reject probes from hosts without it.
- HTTPS in front of the server (the site is served over HTTPS, so browsers block calls to plain HTTP). Caddy does this in one line.

## Run

    HELO_HOST=verify.example.com PROBE_FROM=verify@example.com \
    ALLOWED_ORIGIN=https://vgclaude.github.io TRUST_PROXY=1 python3 server.py

With Caddy as the HTTPS front: `verify.example.com { reverse_proxy localhost:8080 }`.
Or build the Dockerfile and run it with the same environment variables.

Then put the server's address in `site/config.js`:

    window.ADDRESS_CHECK_API = "https://verify.example.com";

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | 8080 | HTTP port |
| `HELO_HOST` | this host's name | Name announced to mail servers. Must resolve and have matching reverse DNS |
| `PROBE_FROM` | `verify@HELO_HOST` | Envelope sender used for probes |
| `ALLOWED_ORIGIN` | `*` | Site allowed to call the API. Set it to your site |
| `RATE_PER_MIN` | 30 | Requests per IP per minute |
| `TRUST_PROXY` | off | Set `1` behind a proxy so the real client IP is rate limited |
| `GREYLIST_WAIT` | 25 | Seconds before retrying a deferred answer |

## API

`GET /verify?email=name@example.com` returns JSON:
`verdict` (`deliverable`, `invalid`, `risky`, `unknown`), `state`, `checks`, `recovered`, `trap_risk`, `mx`.

## Test

    python3 test_server.py

Starts `fake_smtp.py` (a pretend mail server) and checks the server against mailbox-exists, no-mailbox, catch-all,
greylist, blocked, unreachable, recovery and spam-trap cases. If Python reports certificate errors on macOS, run it
with `SSL_CERT_FILE=/etc/ssl/cert.pem`.

## Limits you should know

- Big providers (Outlook.com, Yahoo, iCloud) and some corporate gateways refuse or lie about mailbox probes.
  Those come back `unknown` or, on catch-all hosts, `risky`. No tool can do better without sending real mail.
- Spam-trap detection is pattern-based only. Real trap lists are private and cannot be queried.
- Recovery tries typo fixes and name patterns. It does not search the web.
- Probing from an IP with poor reputation gets blocked. Do not use it for bulk scans.
