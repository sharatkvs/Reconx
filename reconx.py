#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║        ReconX — Web Recon & Security Posture Scanner             ║
╠══════════════════════════════════════════════════════════════════╣
║  Author      : [K V S Sharat Chandra]                                       ║
║  Language    : Python 3 — ZERO external libraries                ║
║  Dependencies: NONE — only Python standard library               ║
║                                                                  ║
║  Usage    : python reconx.py <target>                            ║
║  Examples : python reconx.py example.com                         ║
║             python reconx.py https://example.com                 ║
║                                                                  ║
║  OUTPUT   : Terminal results + saved HTML report                 ║
╚══════════════════════════════════════════════════════════════════╝

    WARNING: Only run on targets you have written permission to test.

  WHAT THIS TOOL CHECKS (10 modules):
  ────────────────────────────────────────────────────────────────
  [1]  DNS Records         A, MX, NS, TXT records
  [2]  Subdomain Finder    Brute-forces 100 common subdomains
  [3]  Port Scanner        20 critical ports with banner grabbing
  [4]  SSL/TLS Inspector   Certificate validity, expiry, issuer
  [5]  Security Headers    8 critical HTTP security headers
  [6]  Tech Fingerprint    Detects server, CMS, framework, CDN
  [7]  Cookie Auditor      HttpOnly / Secure / SameSite flags
  [8]  CORS Checker        Dangerous CORS misconfiguration test
  [9]  Sensitive Paths     Checks .env, .git, admin panels, etc.
  [10] WAF Detector        Identifies Web Application Firewalls
  ────────────────────────────────────────────────────────────────

  HOW TO RUN:
    python3 reconx.py example.com
    python3 reconx.py https://bugbounty-target.com

  NO pip install. NO API key. NO accounts. Just Python.
"""

# ─── Standard Library Only ────────────────────────────────────────────────────
import socket               # DNS resolution and port scanning (TCP connect)
import ssl                  # SSL/TLS certificate inspection
import sys                  # Command-line arguments and exit
import os                   # File operations
import re                   # Regex pattern matching in HTTP responses
import json                 # Structuring scan results for the HTML report
import time                 # Timing the scan
import subprocess           # Running nslookup for MX/NS/TXT DNS records
import concurrent.futures   # Threading — run checks in parallel for speed
from datetime import datetime                    # Certificate expiry, timestamps
from urllib.parse  import urlparse, urlencode    # Parse/build URLs
from urllib.request import urlopen, Request      # HTTP requests (no requests lib)
from urllib.error   import URLError, HTTPError   # Catching HTTP errors
import http.client                               # Low-level HTTP for header checks


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

TIMEOUT     = 4    # Seconds to wait before giving up on any connection
MAX_THREADS = 25   # Parallel threads (higher = faster scan but more noise)

# Browser-like User-Agent so servers don't immediately block us
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# 20 ports most important to security — open ones are often findings
PORTS_TO_SCAN = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "Jupyter",
    27017: "MongoDB",
    9200:  "Elasticsearch",
}

# 100 common subdomains to brute-force
SUBDOMAINS = [
    "www","mail","ftp","admin","api","dev","staging","test","vpn","remote",
    "portal","blog","shop","app","cdn","static","dashboard","jenkins","gitlab",
    "jira","confluence","bitbucket","beta","demo","preview","old","new","secure",
    "auth","login","help","support","docs","wiki","forum","community","chat",
    "status","monitor","grafana","kibana","elastic","redis","db","database",
    "backup","files","upload","download","media","images","assets","video",
    "stream","git","svn","repo","mx","smtp","pop","imap","webmail","exchange",
    "autodiscover","cpanel","whm","plesk","webhosting","panel","control",
    "uat","qa","preprod","sandbox","internal","intranet","corp","office",
    "employee","hr","finance","erp","crm","mobile","m","ws","api2","v1","v2",
    "v3","prod","production","live","server","ns1","ns2","cloud","k8s","docker",
    "proxy","gateway","sso","idp","ldap","ad","dc","mail2","smtp2","relay",
]

# 8 security headers every website must have
# Missing any of these = potential bug bounty finding
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "Forces HTTPS — prevents SSL stripping attacks",
        "risk": "HIGH"
    },
    "Content-Security-Policy": {
        "desc": "Prevents XSS by controlling what resources can load",
        "risk": "HIGH"
    },
    "X-Frame-Options": {
        "desc": "Prevents clickjacking via iframe embedding",
        "risk": "MEDIUM"
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME-type sniffing attacks",
        "risk": "MEDIUM"
    },
    "Referrer-Policy": {
        "desc": "Controls what URL info is leaked in Referer header",
        "risk": "LOW"
    },
    "Permissions-Policy": {
        "desc": "Controls browser features: camera, mic, location",
        "risk": "LOW"
    },
    "X-XSS-Protection": {
        "desc": "Old XSS filter — should be set to block mode",
        "risk": "LOW"
    },
    "Cross-Origin-Opener-Policy": {
        "desc": "Isolates browsing context from cross-origin attacks",
        "risk": "LOW"
    },
}

# Sensitive file/directory paths to probe
# Finding these returning HTTP 200 = valid bug bounty finding
SENSITIVE_PATHS = [
    "/.env",                        # Environment file — DB passwords, API keys
    "/.git/config",                 # Git config — leaks repo info
    "/.git/HEAD",                   # Git HEAD file
    "/wp-config.php",               # WordPress DB credentials
    "/config.php",                  # Generic PHP config
    "/admin",                       # Admin panel
    "/administrator",               # Joomla admin
    "/phpmyadmin",                  # Database admin panel
    "/.htaccess",                   # Apache config
    "/web.config",                  # IIS config
    "/robots.txt",                  # May reveal hidden paths
    "/sitemap.xml",                 # Full page list
    "/.well-known/security.txt",    # Security contact info
    "/server-status",               # Apache mod_status — leaks server info
    "/server-info",                 # Apache server info
    "/.DS_Store",                   # macOS metadata — leaks filenames
    "/backup.zip",                  # Backup archive
    "/backup.sql",                  # Database dump
    "/dump.sql",                    # Database dump
    "/api/swagger",                 # API documentation
    "/swagger/index.html",          # Swagger UI
    "/api-docs",                    # API docs
    "/graphql",                     # GraphQL endpoint
    "/.well-known/jwks.json",       # JWT public keys
    "/actuator",                    # Spring Boot — leaks internal data
    "/actuator/env",                # Spring Boot env — credentials leak
    "/metrics",                     # Prometheus metrics
    "/.bash_history",               # Shell history
    "/package.json",                # Node.js deps — tech stack leak
    "/composer.json",               # PHP deps — tech stack leak
    "/Dockerfile",                  # Docker config
    "/docker-compose.yml",          # Docker compose config
]

# WAF signatures found in response headers or cookie names
WAF_SIGNATURES = {
    "Cloudflare":        ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF":           ["awswaf", "x-amzn-requestid", "x-amz-cf-id"],
    "Akamai":            ["akamai", "x-akamai", "x-check-cacheable"],
    "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
    "F5 BIG-IP":         ["f5", "bigip", "x-wa-info"],
    "Sucuri":            ["x-sucuri-id", "sucuri-clientsupport"],
    "ModSecurity":       ["mod_security", "modsecurity"],
    "Barracuda":         ["barracuda_"],
    "Fastly":            ["x-fastly-request-id"],
}


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP HELPER — replaces the 'requests' library using only stdlib
# ══════════════════════════════════════════════════════════════════════════════

def http_get(url, extra_headers=None, follow_redirects=True, timeout=TIMEOUT):
    """
    Make an HTTP GET request using ONLY Python standard library.

    This replaces the popular 'requests' library entirely.
    Uses urllib.request.urlopen() which is built into Python.

    Returns a dict with:
      - status   : HTTP status code (200, 403, 404 etc.)
      - headers  : dict of response headers (lowercase keys)
      - body     : first 8000 bytes of the response body as string
      - error    : None if successful, error message string if failed
      - url      : final URL after any redirects
    """
    # Build SSL context that does NOT verify certificates
    # We want to scan sites with expired or self-signed certs too
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode    = ssl.CERT_NONE

    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)

    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            body_bytes = resp.read(8000)     # Only read first 8KB
            return {
                "status":  resp.status,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body":    body_bytes.decode("utf-8", errors="ignore"),
                "error":   None,
                "url":     resp.url,
            }
    except HTTPError as e:
        # HTTPError is raised for 4xx/5xx — but we still want those status codes
        return {
            "status":  e.code,
            "headers": {k.lower(): v for k, v in e.headers.items()},
            "body":    "",
            "error":   None,      # Not really an error for our purposes
            "url":     url,
        }
    except URLError as e:
        return {"status": None, "headers": {}, "body": "", "error": str(e.reason), "url": url}
    except Exception as e:
        return {"status": None, "headers": {}, "body": "", "error": str(e), "url": url}


def http_get_no_redirect(url, extra_headers=None):
    """
    Same as http_get but does NOT follow redirects.
    Used for sensitive path checking — 301/302 is also interesting.
    """
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode    = ssl.CERT_NONE

    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)

    parsed = urlparse(url)
    host   = parsed.netloc
    path   = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    use_ssl = parsed.scheme == "https"

    try:
        if use_ssl:
            conn = http.client.HTTPSConnection(host, timeout=TIMEOUT, context=ssl_ctx)
        else:
            conn = http.client.HTTPConnection(host, timeout=TIMEOUT)

        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        body = resp.read(2000).decode("utf-8", errors="ignore")
        conn.close()
        return {"status": resp.status, "headers": resp_headers, "body": body, "error": None}
    except Exception as e:
        return {"status": None, "headers": {}, "body": "", "error": str(e)}


def clean_target(target):
    """
    Strip scheme and trailing slashes from user input.
    'https://example.com/path' → 'example.com'
    """
    target = target.strip().lower()
    if "://" in target:
        parsed = urlparse(target)
        return parsed.netloc or parsed.path
    return target.split("/")[0]


def print_section(title):
    print(f"\n{'━' * 65}")
    print(f"  {title}")
    print(f"{'━' * 65}")


def tick(ok):
    return "✓" if ok else "✗"


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 1 — DNS RECORDS
# ══════════════════════════════════════════════════════════════════════════════

def get_dns_records(domain):
    """
    Resolve A, MX, NS, TXT records for the target domain.

    WHY THIS MATTERS:
      A   → The IP address. Multiple IPs = load balanced / CDN
      MX  → Mail servers — a separate attack surface for phishing tests
      NS  → Name servers — reveals hosting/DNS provider
      TXT → SPF, DKIM, DMARC, Google verification tokens

    socket.gethostbyname_ex() is pure stdlib — no dig/nslookup needed for A records.
    For MX/NS/TXT we call nslookup via subprocess (available on Windows + Linux + Mac).
    """
    print_section("[1/10] DNS Records")
    results = {}

    # A record — IP resolution
    try:
        hostname, aliases, ips = socket.gethostbyname_ex(domain)
        results["A"] = ips
        print(f"  [A]    {domain} → {', '.join(ips)}")
        if aliases:
            print(f"         Aliases: {', '.join(aliases)}")
    except socket.gaierror as e:
        results["A"]     = []
        results["error"] = str(e)
        print(f"  [!]  Cannot resolve {domain}: {e}")
        return results

    # MX, NS, TXT — use nslookup (available everywhere Python runs)
    for rtype in ["MX", "NS", "TXT"]:
        try:
            out = subprocess.run(
                ["nslookup", f"-type={rtype}", domain],
                capture_output=True, text=True, timeout=6
            ).stdout
            lines = [
                l.strip() for l in out.splitlines()
                if l.strip()
                and "Server:" not in l
                and "Address:" not in l
                and "***" not in l
                and ("=" in l or "exchanger" in l or "nameserver" in l or "text" in l)
            ]
            results[rtype] = lines
            if lines:
                print(f"  [{rtype}]   {lines[0]}")
                for l in lines[1:3]:
                    print(f"         {l}")
        except Exception:
            results[rtype] = []

    return results


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 2 — SUBDOMAIN FINDER
# ══════════════════════════════════════════════════════════════════════════════

def find_subdomains(domain):
    """
    Check if each subdomain in our wordlist resolves via DNS.

    HOW IT WORKS:
      For each word like "admin", we try: socket.gethostbyname("admin.example.com")
      If it returns an IP → that subdomain EXISTS.
      We use ThreadPoolExecutor to check all 100 subdomains in parallel.
      Without threads: ~100 × 4sec timeout = 400s. With threads: ~4s total.

    BUG BOUNTY VALUE:
      - dev/staging subdomains often have no WAF, weaker auth
      - admin. subdomains may have exposed dashboards
      - api. subdomains often have more endpoints and looser controls
    """
    print_section("[2/10] Subdomain Finder")

    def check(sub):
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            return {"subdomain": full, "ip": ip}
        except socket.gaierror:
            return None

    print(f"  [*] Checking {len(SUBDOMAINS)} subdomains in parallel...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        results = list(ex.map(check, SUBDOMAINS))

    found = [r for r in results if r]
    if found:
        print(f"  [+] {len(found)} subdomains found:\n")
        for s in found:
            print(f"      {s['subdomain']:<45} {s['ip']}")
    else:
        print("  [-] No common subdomains found")

    return found


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 3 — PORT SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def scan_ports(ip):
    """
    TCP connect scan on 20 high-value ports.

    HOW IT WORKS:
      socket.connect_ex(ip, port) → returns 0 if port is open, non-zero if closed.
      After connecting, we send a newline and read the first bytes — this is called
      "banner grabbing" — many services announce their software version on connect.

    HIGH VALUE OPEN PORTS (often immediate bug bounty findings):
      Redis (6379)         → Usually no auth by default → full DB access
      Elasticsearch (9200) → No auth, all data accessible via HTTP
      MongoDB (27017)      → Old installs have no auth enabled
      Jupyter (8888)       → Often has no password, full code execution
      RDP (3389)           → Remote desktop exposed to internet
    """
    print_section("[3/10] Port Scanner")
    open_ports = []

    def check_port(port_info):
        port, service = port_info
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        if sock.connect_ex((ip, port)) == 0:
            banner = None
            try:
                if port not in [443, 8443, 3389]:
                    sock.sendall(b"\r\n")
                    raw    = sock.recv(256)
                    banner = raw.decode("utf-8", errors="ignore").strip()[:80]
            except Exception:
                pass
            sock.close()
            return {"port": port, "service": service, "banner": banner}
        sock.close()
        return None

    print(f"  [*] Scanning {len(PORTS_TO_SCAN)} ports on {ip}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        results = list(ex.map(check_port, PORTS_TO_SCAN.items()))

    open_ports = [r for r in results if r]

    if open_ports:
        print(f"  [+] {len(open_ports)} open ports:\n")
        for p in sorted(open_ports, key=lambda x: x["port"]):
            banner = f" → {p['banner']}" if p.get("banner") else ""
            print(f"      {p['port']:5d}/tcp  {p['service']:<20}{banner}")
    else:
        print("  [-] No open ports found (all filtered or closed)")

    return open_ports


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 4 — SSL/TLS INSPECTOR
# ══════════════════════════════════════════════════════════════════════════════

def inspect_ssl(domain):
    """
    Connect to port 443 and read the TLS certificate details.

    WHAT WE LOOK FOR:
      Expired cert       → Valid bug bounty finding (security negligence)
      Self-signed cert   → No CA validation → possible MITM risk
      TLS 1.0/1.1        → Outdated versions → potential downgrade attacks
      SANs               → Subject Alternative Names reveal all domains
                           on this cert — instant subdomain enumeration!
      Short expiry       → Cert expiring in <30 days — operational risk

    Python's ssl module handles all of this — pure stdlib, no openssl command needed.
    """
    print_section("[4/10] SSL/TLS Certificate Inspector")
    result = {"valid": False}

    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(TIMEOUT)
        conn.connect((domain, 443))

        cert       = conn.getpeercert()
        tls_ver    = conn.version()
        cipher     = conn.cipher()
        conn.close()

        not_after   = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z")
        not_before  = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        days_left   = (not_after - datetime.utcnow()).days
        subject     = dict(x[0] for x in cert.get("subject",  []))
        issuer      = dict(x[0] for x in cert.get("issuer",   []))
        sans        = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

        result = {
            "valid":       True,
            "common_name": subject.get("commonName", "?"),
            "issuer":      issuer.get("organizationName", "?"),
            "not_before":  str(not_before.date()),
            "not_after":   str(not_after.date()),
            "days_left":   days_left,
            "tls_version": tls_ver,
            "cipher":      cipher[0] if cipher else "?",
            "sans":        sans,
        }

        expiry_note = "  EXPIRING SOON" if 0 < days_left < 30 else (
                      "  EXPIRED"        if days_left <= 0       else "")

        print(f"  [✓] Certificate found")
        print(f"      Common Name  : {result['common_name']}")
        print(f"      Issued By    : {result['issuer']}")
        print(f"      Expires      : {result['not_after']}  ({days_left} days){expiry_note}")
        print(f"      TLS Version  : {tls_ver}  |  Cipher: {result['cipher']}")
        if sans:
            preview = ", ".join(sans[:6])
            more    = f"  (+{len(sans)-6} more)" if len(sans) > 6 else ""
            print(f"      Alt Names    : {preview}{more}")

    except ssl.SSLCertVerificationError as e:
        result["error"] = str(e)
        print(f"  [✗] Certificate INVALID: {e}")
        print(f"      → Self-signed or domain mismatch — potential finding!")
    except ConnectionRefusedError:
        result["error"] = "Port 443 closed"
        print("  [-] HTTPS not available (port 443 closed)")
    except Exception as e:
        result["error"] = str(e)
        print(f"  [!] SSL error: {e}")

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 5 — SECURITY HEADERS
# ══════════════════════════════════════════════════════════════════════════════

def check_security_headers(url):
    """
    Fetch the homepage and check which security headers are set.

    Each missing header is a potential bug bounty finding:
      Missing HSTS                → SSL stripping possible
      Missing CSP                 → XSS easier to exploit (no content policy)
      Missing X-Frame-Options     → Site can be embedded → clickjacking
      Missing X-Content-Type-Options → MIME confusion attacks

    We use our stdlib http_get() function — no requests library needed.
    """
    print_section("[5/10] Security Headers Analysis")
    results = {"present": {}, "missing": {}}

    resp = http_get(url)
    if resp["error"]:
        print(f"  [!] Could not reach {url}: {resp['error']}")
        return results

    hdrs = resp["headers"]    # Already lowercase keys from http_get()

    for header, info in SECURITY_HEADERS.items():
        key    = header.lower()
        value  = hdrs.get(key)
        if value:
            results["present"][header] = value
            print(f"  [✓] PRESENT  [{info['risk']:6s}]  {header}")
        else:
            results["missing"][header] = info
            print(f"  [✗] MISSING  [{info['risk']:6s}]  {header}")
            print(f"               └─ {info['desc']}")

    score = len(results["present"])
    total = len(SECURITY_HEADERS)
    bar   = "█" * score + "░" * (total - score)
    print(f"\n  Score : {bar}  {score}/{total} headers present")

    return results


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 6 — TECHNOLOGY FINGERPRINTING
# ══════════════════════════════════════════════════════════════════════════════

def fingerprint_tech(url):
    """
    Identify what server, CMS, framework, and CDN the target uses.

    We look in three places:
      1. Response headers  → Server: nginx/1.14, X-Powered-By: PHP/7.4
      2. Cookie names      → PHPSESSID = PHP,  JSESSIONID = Java
      3. HTML body         → wp-content = WordPress, ng-version = Angular

    WHY IT MATTERS:
      WordPress → check xmlrpc.php brute force, plugin CVEs
      PHP 5.x   → outdated, many known RCE vulnerabilities
      Old Nginx  → check CVEs for that specific version
      No CDN     → server IP is exposed → direct DDoS / bypass target
    """
    print_section("[6/10] Technology Fingerprinting")
    tech = {}

    resp = http_get(url)
    if resp["error"]:
        print(f"  [!] Could not fetch page: {resp['error']}")
        return tech

    hdrs = resp["headers"]
    body = resp["body"]

    # Server and framework headers
    for h in ["server", "x-powered-by", "x-generator", "x-drupal-cache", "x-wp-total"]:
        if h in hdrs:
            label = h.replace("x-", "").replace("-", " ").title()
            tech[label] = hdrs[h]
            print(f"  [+] {label:<16}: {hdrs[h]}")

    # Cookie-based detection — check Set-Cookie header
    set_cookie = hdrs.get("set-cookie", "").upper()
    if "PHPSESSID"        in set_cookie:
        tech["Language"] = "PHP";          print("  [+] Language        : PHP  (PHPSESSID cookie)")
    if "JSESSIONID"       in set_cookie:
        tech["Language"] = "Java/Tomcat";  print("  [+] Language        : Java / Apache Tomcat")
    if "ASP.NET_SESSIONID" in set_cookie or "ASPXAUTH" in set_cookie:
        tech["Framework"] = "ASP.NET";     print("  [+] Framework       : ASP.NET")

    # HTML body pattern matching
    cms_sigs = {
        "WordPress":  [r"wp-content", r"wp-includes", r"/wp-json/"],
        "Joomla":     [r"Joomla!", r"/components/com_"],
        "Drupal":     [r"Drupal\.settings", r"/sites/default/files"],
        "Magento":    [r"Mage\.Cookies", r"/skin/frontend/"],
        "Shopify":    [r"cdn\.shopify\.com"],
        "React":      [r"__REACT_DEVTOOLS", r"react-dom"],
        "Vue.js":     [r"__vue__", r"data-v-"],
        "Angular":    [r"ng-version", r"ng-app"],
        "Bootstrap":  [r"bootstrap\.min\.css"],
        "jQuery":     [r"jquery\.min\.js", r"jquery-\d"],
        "Laravel":    [r"laravel_session", r"XSRF-TOKEN"],
        "Django":     [r"csrfmiddlewaretoken", r"django"],
    }
    for name, patterns in cms_sigs.items():
        for pat in patterns:
            if re.search(pat, body, re.IGNORECASE):
                tech[name] = True
                print(f"  [+] Detected        : {name}")
                break

    # CDN detection from headers
    all_hdrs_str = str(hdrs).lower()
    if "cloudflare" in all_hdrs_str or "cf-ray" in hdrs:
        tech["CDN"] = "Cloudflare"; print("  [+] CDN             : Cloudflare")
    elif "akamai"   in all_hdrs_str:
        tech["CDN"] = "Akamai";     print("  [+] CDN             : Akamai")
    elif "fastly"   in all_hdrs_str:
        tech["CDN"] = "Fastly";     print("  [+] CDN             : Fastly")
    elif "x-amz"    in all_hdrs_str:
        tech["CDN"] = "AWS/CloudFront"; print("  [+] CDN             : AWS CloudFront")

    if not tech:
        print("  [-] No technology signatures detected")

    return tech


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 7 — COOKIE AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

def audit_cookies(url):
    """
    Inspect cookies for missing security flags.

    THREE FLAGS EVERY SESSION COOKIE MUST HAVE:
      HttpOnly  → JavaScript cannot read the cookie
                  Without it: XSS can steal the session → account takeover
      Secure    → Cookie only sent over HTTPS
                  Without it: cookie travels in plaintext over HTTP → interception
      SameSite  → Controls if cookie is sent on cross-site requests
                  Without it: CSRF attacks possible

    HOW WE READ RAW COOKIES WITHOUT 'requests' LIBRARY:
      The Set-Cookie header is in the raw HTTP response headers.
      We parse http_client.HTTPSConnection response directly to get raw headers.
    """
    print_section("[7/10] Cookie Security Auditor")
    audit_results = []

    # Use http.client directly to get raw Set-Cookie headers
    # urlopen does not expose raw multi-value headers easily
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode    = ssl.CERT_NONE

    parsed = urlparse(url)
    host   = parsed.netloc

    try:
        conn = http.client.HTTPSConnection(host, timeout=TIMEOUT, context=ssl_ctx)
        conn.request("GET", "/", headers={"User-Agent": USER_AGENT})
        resp         = conn.getresponse()
        raw_headers  = resp.getheaders()     # List of (name, value) tuples
        conn.close()
    except Exception as e:
        print(f"  [!] Could not fetch cookies: {e}")
        return audit_results

    # Extract all Set-Cookie headers (there may be multiple)
    set_cookie_headers = [v for k, v in raw_headers if k.lower() == "set-cookie"]

    if not set_cookie_headers:
        print("  [-] No cookies set on homepage")
        return audit_results

    print(f"  [*] Found {len(set_cookie_headers)} cookie(s):\n")

    for raw in set_cookie_headers:
        raw_lower = raw.lower()

        # Cookie name is everything before the first =
        name      = raw.split("=")[0].strip()
        httponly  = "httponly"    in raw_lower
        secure    = "secure"      in raw_lower
        ss_match  = re.search(r"samesite=(\w+)", raw_lower)
        samesite  = ss_match.group(1) if ss_match else None

        issues = []
        if not httponly:  issues.append("Missing HttpOnly  → XSS can steal session cookie")
        if not secure:    issues.append("Missing Secure    → cookie sent over HTTP (cleartext)")
        if not samesite:  issues.append("Missing SameSite  → CSRF attack possible")

        audit_results.append({
            "name":     name,
            "httponly": httponly,
            "secure":   secure,
            "samesite": samesite,
            "issues":   issues,
        })

        icon = "✓" if not issues else ""
        print(f"  [{icon}] {name}")
        print(f"       HttpOnly:{tick(httponly)}  Secure:{tick(secure)}  SameSite:{samesite or 'Not set'}")
        for issue in issues:
            print(f"         {issue}")
        print()

    return audit_results


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 8 — CORS CHECKER
# ══════════════════════════════════════════════════════════════════════════════

def check_cors(url):
    """
    Test for CORS (Cross-Origin Resource Sharing) misconfiguration.

    WHAT IS CORS MISCONFIGURATION?
      Normally, JavaScript on evil.com CANNOT read responses from bank.com.
      CORS headers tell the browser: "it's okay for evil.com to read my data."
      If a server does this AND allows credentials → attacker can steal data.

    HOW WE TEST:
      We send GET requests with fake Origin headers and check if the server
      reflects them back in 'Access-Control-Allow-Origin'.

      Test 1: Origin: https://evil.com          → basic reflection
      Test 2: Origin: null                       → null origin bypass
      Test 3: Origin: https://evil-target.com    → suffix match bypass

    SEVERITY:
      ACAO reflects origin + ACAC: true   → HIGH (authenticated data leak)
      ACAO: *  with credentials           → CRITICAL (shouldn't be possible but misconfigured)
      ACAO reflects origin, no creds      → LOW / informational
    """
    print_section("[8/10] CORS Misconfiguration Checker")
    findings = []

    parsed   = urlparse(url)
    domain   = parsed.netloc.lstrip("www.")

    test_cases = [
        ("https://evil.com",                          "Basic reflection test"),
        ("null",                                       "Null origin bypass"),
        (f"https://evil{domain}",                     "Suffix match bypass"),
        (f"https://{domain}.evil.com",                "Subdomain bypass"),
    ]

    for origin, label in test_cases:
        resp = http_get(url, extra_headers={"Origin": origin})
        if resp["error"]:
            continue

        acao = resp["headers"].get("access-control-allow-origin", "")
        acac = resp["headers"].get("access-control-allow-credentials", "").lower()

        finding = {
            "test":         label,
            "origin_sent":  origin,
            "acao":         acao,
            "credentials":  acac == "true",
            "vulnerable":   False,
            "severity":     "INFO",
        }

        if acao == origin and acac == "true":
            finding["vulnerable"] = True
            finding["severity"]   = "HIGH"
            print(f"   VULNERABLE [{finding['severity']}]  {label}")
            print(f"     Origin Sent  : {origin}")
            print(f"     ACAO Header  : {acao}")
            print(f"     Credentials  : {acac}  ← attacker can read authenticated responses!")
        elif acao == "*" and acac == "true":
            finding["vulnerable"] = True
            finding["severity"]   = "CRITICAL"
            print(f"   CRITICAL — Wildcard CORS with credentials: {label}")
        elif acao == origin:
            finding["severity"] = "LOW"
            print(f"    Origin reflected (no credentials): {origin}")
        else:
            print(f"  [✓] {label} — Not reflected")

        findings.append(finding)

    if not any(f["vulnerable"] for f in findings):
        print("  [✓] No dangerous CORS configuration detected")

    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 9 — SENSITIVE PATHS
# ══════════════════════════════════════════════════════════════════════════════

def check_sensitive_paths(base_url):
    """
    Probe for exposed sensitive files and admin panels.

    STATUS CODE MEANING FOR BUG BOUNTY:
      200 OK      → File EXISTS and readable → FINDING (submit it!)
      401/403     → File exists but access denied → try bypass techniques
      301/302     → Redirect → investigate where it goes
      500 Error   → Something exists and crashed the server
      404         → Nothing there (skip)

    CRITICAL FINDS:
      /.env returning 200        → Database passwords, API keys exposed → Critical
      /.git/config returning 200 → Source code leak → High/Critical
      /actuator/env returning 200→ Spring Boot credentials exposed → Critical
      /graphql returning 200     → Test for introspection, injection
    """
    print_section("[9/10] Sensitive Paths & Exposed Files")

    base = base_url.rstrip("/")
    found = []

    def probe(path):
        resp = http_get_no_redirect(base + path)
        if resp["error"] or resp["status"] is None:
            return None
        status = resp["status"]
        if status in [404, 410, 400, 406]:
            return None

        sev = "INFO"
        if status == 200:
            length = len(resp["body"])
            if any(x in path for x in [".env", ".git", "config", "backup", ".sql", "history", "Dockerfile"]):
                sev = "CRITICAL"
            elif any(x in path for x in ["admin", "phpmyadmin", "actuator", "swagger", "graphql"]):
                sev = "HIGH"
            elif length > 0:
                sev = "MEDIUM"
        elif status in [401, 403]:
            sev = "LOW"
        elif status in [301, 302]:
            sev = "INFO"

        return {"path": path, "status": status, "severity": sev, "size": len(resp["body"])}

    print(f"  [*] Probing {len(SENSITIVE_PATHS)} paths...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        results = list(ex.map(probe, SENSITIVE_PATHS))

    found = [r for r in results if r]

    if found:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        found.sort(key=lambda x: order.index(x["severity"]))
        print(f"\n  [!] {len(found)} interesting paths:\n")
        for f in found:
            sev_pad = f"[{f['severity']:8s}]"
            print(f"  {sev_pad}  HTTP {f['status']}  {f['path']:<40} ({f['size']} bytes)")
    else:
        print("  [✓] No sensitive paths found")

    return found


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 10 — WAF DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

def detect_waf(url):
    """
    Detect if a Web Application Firewall is protecting the site.

    METHOD 1 — Header Signatures:
      WAFs inject their own response headers:
        Cloudflare  → cf-ray header in every response
        Akamai      → x-akamai header
        Imperva     → set-cookie includes incap_ses

    METHOD 2 — Attack Probe:
      Send a request with obvious SQLi + XSS payloads in the URL.
      If the normal request → 200 OK
      But attack request   → 403 Forbidden
      → A WAF is blocking attack traffic!

    PENTEST VALUE:
      Knowing the WAF tells you what bypass techniques to try.
      Some WAF configs only protect certain paths — find the unprotected ones.
    """
    print_section("[10/10] WAF Detector")
    result = {"detected": False, "waf_name": "Unknown", "method": None}

    # Method 1: Normal request, check headers for WAF signatures
    resp = http_get(url)
    if not resp["error"]:
        headers_str = json.dumps(resp["headers"]).lower()
        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in headers_str:
                    result = {"detected": True, "waf_name": waf_name, "method": "Header signature"}
                    break
            if result["detected"]:
                break

    # Method 2: Attack probe
    attack_url = url + "/?id=1'%20OR%20'1'='1&q=<script>alert(1)</script>&cmd=;id;"
    atk_resp   = http_get(attack_url)
    normal_status = resp.get("status")    if resp   else None
    attack_status = atk_resp.get("status") if atk_resp else None

    if normal_status == 200 and attack_status in [403, 406, 429, 503]:
        result["blocks_attacks"] = True
        if not result["detected"]:
            result = {"detected": True, "waf_name": "Unknown WAF", "method": "Attack blocked"}

    if result["detected"]:
        print(f"  [+] WAF DETECTED: {result['waf_name']}")
        print(f"      Method       : {result['method']}")
        if result.get("blocks_attacks"):
            print(f"      Blocks attacks : Yes → HTTP {attack_status} on attack payload")
        print(f"      → You will need WAF bypass techniques to test properly")
    else:
        print("  [-] No WAF detected — direct access to application")
        print("      → Easier to test; no bypass needed")

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  HTML REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_html_report(domain, data):
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"reconx_{domain.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    sensitive  = data.get("sensitive_paths", [])
    critical_n = sum(1 for x in sensitive if x.get("severity") == "CRITICAL")
    high_n     = sum(1 for x in sensitive if x.get("severity") == "HIGH")
    miss_hdrs  = len(data.get("headers", {}).get("missing", {}))
    cors_vulns = sum(1 for x in data.get("cors", []) if x.get("vulnerable"))
    sub_count  = len(data.get("subdomains", []))
    port_count = len(data.get("ports", []))

    def tag(sev):
        return f'<span class="tag {sev.lower()}">{sev}</span>'

    rows_headers = ""
    for h, info in SECURITY_HEADERS.items():
        if h in data.get("headers", {}).get("present", {}):
            rows_headers += f"<tr><td>{h}</td><td>{tag('ok')} PRESENT</td><td>{info['risk']}</td></tr>"
        else:
            rows_headers += f"<tr><td>{h}</td><td>{tag('missing')} MISSING</td><td style='color:#f85149'>{info['risk']}</td></tr>"

    rows_ports = "".join(
        f"<tr><td>{p['port']}/tcp</td><td>{p['service']}</td><td><code>{p.get('banner') or '—'}</code></td></tr>"
        for p in sorted(data.get("ports", []), key=lambda x: x["port"])
    )

    rows_subs = "".join(
        f"<tr><td>{s['subdomain']}</td><td>{s['ip']}</td></tr>"
        for s in data.get("subdomains", [])
    )

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    rows_paths = "".join(
        f"<tr><td><code>{f['path']}</code></td><td>{f['status']}</td><td>{f['size']} B</td><td>{tag(f['severity'])}</td></tr>"
        for f in sorted(sensitive, key=lambda x: order.index(x["severity"]))
    )

    ssl   = data.get("ssl", {})
    days  = ssl.get("days_left", 0)
    dcol  = "color:#f85149" if days < 30 else "color:#3fb950"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>ReconX — {domain}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',monospace;background:#0d1117;color:#c9d1d9;line-height:1.7}}
  .hdr{{background:linear-gradient(135deg,#161b22,#21262d);padding:36px 40px;border-bottom:1px solid #30363d}}
  .hdr h1{{font-size:1.8rem;color:#58a6ff}}.hdr p{{color:#8b949e;margin-top:6px}}
  .wrap{{max-width:1080px;margin:0 auto;padding:28px 20px}}
  .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:28px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px;text-align:center}}
  .card .n{{font-size:2.4rem;font-weight:bold}}.card .l{{font-size:.82rem;color:#8b949e;margin-top:4px}}
  .red{{color:#f85149}}.ora{{color:#f0883e}}.yel{{color:#d29922}}.grn{{color:#3fb950}}.blu{{color:#58a6ff}}
  .sec{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:18px}}
  .sec h2{{padding:14px 18px;background:#21262d;border-bottom:1px solid #30363d;font-size:.95rem;color:#e6edf3;border-radius:8px 8px 0 0}}
  .sec-b{{padding:18px}}
  table{{width:100%;border-collapse:collapse;font-size:.88rem}}
  th{{background:#21262d;color:#8b949e;text-align:left;padding:7px 12px;font-weight:400}}
  td{{padding:7px 12px;border-bottom:1px solid #21262d}}tr:last-child td{{border:0}}
  .tag{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.74rem;font-weight:700}}
  .tag.critical{{background:#490202;color:#f85149;border:1px solid #f85149}}
  .tag.high{{background:#341a00;color:#f0883e;border:1px solid #f0883e}}
  .tag.medium{{background:#2e2300;color:#d29922;border:1px solid #d29922}}
  .tag.low{{background:#0f2a1a;color:#3fb950;border:1px solid #3fb950}}
  .tag.info{{background:#0d2035;color:#58a6ff;border:1px solid #58a6ff}}
  .tag.ok{{background:#0f2a1a;color:#3fb950;border:1px solid #3fb950}}
  .tag.missing{{background:#490202;color:#f85149;border:1px solid #f85149}}
  pre{{background:#0d1117;padding:12px;border-radius:4px;overflow-x:auto;font-size:.78rem;color:#8b949e}}
  footer{{text-align:center;padding:18px;color:#484f58;font-size:.78rem}}
  code{{background:#21262d;padding:1px 5px;border-radius:3px;font-size:.84rem}}
</style></head>
<body>
<div class="hdr">
  <h1>⚡ ReconX — Security Recon Report</h1>
  <p>Target: <strong style="color:#58a6ff">{domain}</strong> &nbsp;|&nbsp; {ts}</p>
</div>
<div class="wrap">
  <div class="cards">
    <div class="card"><div class="n red">{critical_n}</div><div class="l">Critical Findings</div></div>
    <div class="card"><div class="n ora">{high_n}</div><div class="l">High Findings</div></div>
    <div class="card"><div class="n yel">{miss_hdrs}</div><div class="l">Missing Headers</div></div>
    <div class="card"><div class="n blu">{sub_count}</div><div class="l">Subdomains Found</div></div>
    <div class="card"><div class="n grn">{port_count}</div><div class="l">Open Ports</div></div>
    <div class="card"><div class="n {'red' if cors_vulns else 'grn'}">{cors_vulns}</div><div class="l">CORS Issues</div></div>
  </div>

  <div class="sec"><h2> SSL / TLS Certificate</h2><div class="sec-b">
    <table>
      <tr><th>Common Name</th><td>{ssl.get('common_name','N/A')}</td></tr>
      <tr><th>Issuer</th><td>{ssl.get('issuer','N/A')}</td></tr>
      <tr><th>Expires</th><td style="{dcol}">{ssl.get('not_after','N/A')} &nbsp; ({days} days remaining)</td></tr>
      <tr><th>TLS Version</th><td>{ssl.get('tls_version','N/A')}</td></tr>
      <tr><th>Alt Names (SANs)</th><td>{', '.join(ssl.get('sans',[])[:8]) or 'None'}</td></tr>
    </table></div></div>

  <div class="sec"><h2> Security Headers</h2><div class="sec-b">
    <table><tr><th>Header</th><th>Status</th><th>Risk</th></tr>
    {rows_headers}</table></div></div>

  {'<div class="sec"><h2> Subdomains Found</h2><div class="sec-b"><table><tr><th>Subdomain</th><th>IP</th></tr>' + rows_subs + '</table></div></div>' if rows_subs else ''}
  {'<div class="sec"><h2> Open Ports</h2><div class="sec-b"><table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>' + rows_ports + '</table></div></div>' if rows_ports else ''}
  {'<div class="sec"><h2> Sensitive Paths</h2><div class="sec-b"><table><tr><th>Path</th><th>Status</th><th>Size</th><th>Severity</th></tr>' + rows_paths + '</table></div></div>' if rows_paths else ''}

  <div class="sec"><h2> Full Scan Data (JSON)</h2><div class="sec-b">
    <pre>{json.dumps(data, indent=2, default=str)}</pre>
  </div></div>
</div>
<footer>ReconX &nbsp;|&nbsp; Authorized testing only &nbsp;|&nbsp; {ts}</footer>
</body></html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║        ReconX — Web Recon & Security Posture Scanner             ║
║        Zero dependencies  |  Pure Python stdlib only             ║
╚══════════════════════════════════════════════════════════════════╝""")

    if len(sys.argv) < 2:
        print("\n  Usage   : python3 reconx.py <target>")
        print("  Example : python3 reconx.py example.com")
        sys.exit(1)

    domain   = clean_target(sys.argv[1])
    base_url = f"https://{domain}"

    print(f"\n  Target : {domain}")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n    Only scan targets you have written permission to test!")

    # Resolve IP before starting — needed for port scan
    try:
        target_ip = socket.gethostbyname(domain)
        print(f"\n  [+] Resolved → {target_ip}")
    except socket.gaierror:
        print(f"\n  [!] Cannot resolve {domain}. Check the domain name.")
        sys.exit(1)

    start = time.time()
    data  = {}

    data["dns"]            = get_dns_records(domain)
    data["subdomains"]     = find_subdomains(domain)
    data["ports"]          = scan_ports(target_ip)
    data["ssl"]            = inspect_ssl(domain)
    data["headers"]        = check_security_headers(base_url)
    data["tech"]           = fingerprint_tech(base_url)
    data["cookies"]        = audit_cookies(base_url)
    data["cors"]           = check_cors(base_url)
    data["sensitive_paths"]= check_sensitive_paths(base_url)
    data["waf"]            = detect_waf(base_url)

    elapsed     = round(time.time() - start, 1)
    report_file = generate_html_report(domain, data)

    print(f"\n{'━'*65}")
    print(f"  ✓ Scan complete in {elapsed}s")
    print(f"  ✓ Report saved  : {report_file}")
    print(f"  → Open the HTML file in any browser to view results")
    print(f"{'━'*65}\n")


if __name__ == "__main__":
    main()
