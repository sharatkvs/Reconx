# ReconX — Web Recon & Security Posture Scanner

A Python reconnaissance tool I built for bug bounty hunting and penetration testing.
No external libraries. No API keys. No setup headaches. Just Python.

Point it at a domain and it runs 10 security checks automatically,
then saves everything into a clean HTML report you can actually read.

---

## What it checks

| # | Module | What it finds |
|---|--------|---------------|
| 1 | DNS Records | A, MX, NS, TXT records |
| 2 | Subdomain Finder | Brute-forces 100 common subdomains via DNS |
| 3 | Port Scanner | 20 critical ports with service banner grabbing |
| 4 | SSL/TLS Inspector | Cert validity, expiry, issuer, TLS version, SANs |
| 5 | Security Headers | 8 HTTP security headers that should be present |
| 6 | Tech Fingerprinting | Server, CMS, framework, language, CDN |
| 7 | Cookie Auditor | HttpOnly, Secure, SameSite flags on every cookie |
| 8 | CORS Checker | Tests for dangerous CORS misconfiguration |
| 9 | Sensitive Paths | Checks for .env, .git, admin panels, backup files |
| 10 | WAF Detector | Identifies Cloudflare, Akamai, ModSecurity etc. |

---

## Requirements

Just Python 3. That's it.

```bash
python3 --version   # anything 3.6+ works
```

No pip install. No virtual environment. No dependencies at all.
The entire tool runs on Python's standard library.

---

## Installation

```bash
git clone https://github.com/yourusername/reconx.git
cd reconx
```

Done. Nothing else to do.

---

## How to use it

Basic usage — point at any domain:

```bash
python3 reconx.py example.com
```

With https:// in the URL — it handles that too:

```bash
python3 reconx.py https://example.com
```

That's all there is to it. It'll run all 10 modules and print results
to the terminal in real time. When it finishes, it saves an HTML report
in the same folder.

---

## What the output looks like

While it's running you'll see something like this:

```
╔══════════════════════════════════════════════════════════════════╗
║        ReconX — Web Recon & Security Posture Scanner             ║
╚══════════════════════════════════════════════════════════════════╝

  Target : example.com
  Time   : 2025-01-15 14:32:11

  [+] Resolved → 93.184.216.34

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [1/10] DNS Records
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [A]    example.com → 93.184.216.34

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [2/10] Subdomain Finder
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [*] Checking 100 subdomains in parallel...
  [+] 3 subdomains found:

      api.example.com                               93.184.216.50
      dev.example.com                               93.184.216.51
      admin.example.com                             93.184.216.52

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [5/10] Security Headers Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [✓] PRESENT  [HIGH  ]  Strict-Transport-Security
  [✗] MISSING  [HIGH  ]  Content-Security-Policy
               └─ Prevents XSS by controlling what resources can load
  [✗] MISSING  [MEDIUM]  X-Frame-Options
               └─ Prevents clickjacking via iframe embedding

  Score : ████████░░░░░░░░  3/8 headers present

...

  ✓ Scan complete in 6.3s
  ✓ Report saved : reconx_example_com_20250115_143217.html
```

---

## The HTML report

When the scan finishes, it saves an HTML file you can open in any browser.
It has a dark theme with colour-coded severity cards at the top, then
detailed tables for each module below.

Severity colours:

- 🔴 Critical — needs immediate attention (exposed .env, unauthenticated Redis)
- 🟠 High — significant finding (missing CSP, open admin panel)
- 🟡 Medium — worth noting (missing X-Frame-Options, HTTP-only missing)
- 🟢 Low — informational (missing Referrer-Policy)

---

## What each module actually does

### Subdomain Finder
Checks names like `admin`, `api`, `dev`, `staging`, `dashboard` against the target domain
using DNS resolution. If `admin.example.com` resolves to an IP, that subdomain exists.

Runs 25 checks at the same time using threading so it finishes in seconds
instead of minutes.

Why this matters: dev and staging subdomains almost always skip the WAF
and have weaker auth than production.

### Port Scanner
Tries connecting to 20 common ports and records which ones accept connections.
Also does banner grabbing — reads the first few bytes the service sends on connect,
which often includes the software name and version.

High value ports to find open:
- `6379` Redis — usually no auth by default
- `9200` Elasticsearch — completely public in many setups
- `27017` MongoDB — old installs have no auth
- `8888` Jupyter Notebook — often no password

### Security Headers
Fetches the homepage and checks for 8 headers every site should return.
Each missing header is noted with an explanation of what attack it enables.

Missing `Content-Security-Policy` = XSS is easier to exploit.
Missing `X-Frame-Options` = clickjacking is possible.
These are valid bug bounty findings on most programs.

### CORS Checker
Sends requests with fake `Origin` headers like `https://evil.com` and checks if the
server reflects them back in `Access-Control-Allow-Origin`.

If it does AND `Access-Control-Allow-Credentials: true` is set, an attacker's
website can make JavaScript requests to the target on behalf of a logged-in user
and read the response. That's a High severity finding.

### Cookie Auditor
Reads the raw `Set-Cookie` headers and checks each cookie for three flags:

- `HttpOnly` — without this, JavaScript can read the cookie. XSS = account takeover.
- `Secure` — without this, cookie is sent over plain HTTP. Public WiFi = session theft.
- `SameSite` — without this, CSRF attacks can work.

### Sensitive Paths
Sends a request to each path and logs any that return something other than 404.
Things like `/.env`, `/.git/config`, `/phpmyadmin`, `/actuator/env`.

Finding `/.env` returning `HTTP 200` is a critical finding on any bug bounty program.
It usually contains database passwords, API keys, and cloud credentials.

### WAF Detector
Checks response headers for WAF-specific signatures (Cloudflare adds `cf-ray`,
Imperva adds `incap_ses` cookies etc.), and also sends an obvious attack payload
to see if it gets blocked with a 403.

Knowing the WAF tells you what bypass techniques to try and whether certain
paths might be unprotected.

---

## Port reference

| Port | Service | Why it matters |
|------|---------|----------------|
| 21 | FTP | Often allows anonymous login, cleartext credentials |
| 22 | SSH | Try default credentials, key-based attacks |
| 3306 | MySQL | Direct database access if exposed |
| 3389 | RDP | Remote desktop exposed to internet |
| 6379 | Redis | No auth by default in many installs |
| 8888 | Jupyter | Code execution, often no password |
| 9200 | Elasticsearch | Full data access, often unauthenticated |
| 27017 | MongoDB | No auth in many older deployments |

---

## Security headers reference

| Header | Missing = this attack is easier |
|--------|--------------------------------|
| Strict-Transport-Security | SSL stripping |
| Content-Security-Policy | Cross-site scripting (XSS) |
| X-Frame-Options | Clickjacking |
| X-Content-Type-Options | MIME type confusion |
| Referrer-Policy | URL info leaks |
| Permissions-Policy | Feature abuse (camera, mic) |
| X-XSS-Protection | Reflected XSS on older browsers |
| Cross-Origin-Opener-Policy | Cross-origin window access |

---

## Sensitive paths checked

```
/.env                 /wp-config.php        /phpmyadmin
/.git/config          /config.php           /server-status
/.git/HEAD            /admin                /actuator
/backup.zip           /administrator        /actuator/env
/backup.sql           /.htaccess            /metrics
/dump.sql             /web.config           /graphql
/package.json         /robots.txt           /swagger/index.html
/composer.json        /sitemap.xml          /api-docs
/Dockerfile           /.well-known/jwks.json
/docker-compose.yml   /.bash_history
```

---

## Notes

- Only use this on targets you have written permission to test
- Bug bounty programs: check the scope before scanning
- The subdomain finder only uses DNS — it does not send HTTP requests to subdomains
- Port scanning may be detected by IDS/IPS — not suitable for stealth engagements
- Run from a VPN if you don't want your home IP in access logs

---

## How it's built

Everything uses Python's standard library:

- `socket` — DNS lookups and TCP port scanning
- `ssl` — Certificate inspection
- `http.client` — Raw HTTP connections for cookie headers
- `urllib.request` — HTTP GET requests
- `concurrent.futures` — Parallel threading
- `subprocess` — DNS record lookups via nslookup
- `re` — Pattern matching in HTML and headers
- `json` — Structuring scan results

No pip install means no dependency conflicts, no version issues,
and it works on any machine where Python 3 is installed.

---

## License

For educational purposes and authorised security testing only.
