# Bug Bounty Vulnerability Playbook Index

**Location:** `~/BugBounty/playbooks/`
**Last Updated:** 2026-03-13
**Purpose:** Maps vulnerability types to playbook files. Reference during recon, testing, and reporting phases.

---

## Quick Reference

| Vulnerability | Playbook | Typical Severity | CWE |
|---|---|---|---|
| CORS Misconfiguration | [cors.md](cors.md) | Medium–Critical | CWE-942 |
| SQL Injection | [sqli.md](sqli.md) | High–Critical | CWE-89 |
| Cross-Site Scripting | [xss.md](xss.md) | Medium–High | CWE-79 |
| IDOR / Broken Access Control | [idor.md](idor.md) | Medium–Critical | CWE-639 |
| JWT Vulnerabilities | [jwt.md](jwt.md) | High–Critical | CWE-347 |
| SSRF | [ssrf.md](ssrf.md) | High–Critical | CWE-918 |
| Path Traversal / LFI | [path_traversal.md](path_traversal.md) | Medium–Critical | CWE-22 |
| Authentication Bypass | [auth_bypass.md](auth_bypass.md) | Medium–Critical | CWE-287 |
| Rate Limit Bypass | [rate_limit.md](rate_limit.md) | Low–High | CWE-307 |

---

## By Attack Phase

### Recon / Passive
- Check CORS headers on all subdomains → [cors.md](cors.md)
- Find JWT public keys in well-known endpoints → [jwt.md](jwt.md)
- Identify file-serving parameters → [path_traversal.md](path_traversal.md)
- Find redirect parameters in JS bundles → [auth_bypass.md](auth_bypass.md)
- Discover SSRF-prone features (import URL, webhooks, previews) → [ssrf.md](ssrf.md)

### Active Testing
- Test all input parameters for injection → [sqli.md](sqli.md), [xss.md](xss.md)
- Test all resource access endpoints for ownership checks → [idor.md](idor.md)
- Test rate-limited endpoints (login, OTP, reset) → [rate_limit.md](rate_limit.md)
- Test internal network access from SSRF surface → [ssrf.md](ssrf.md)
- Test JWT algorithm and header attacks → [jwt.md](jwt.md)

### High-Value Chains
- CORS + IDOR: CORS reflection provides same-origin context to exploit IDOR
- XSS + CORS: XSS on same origin bypasses SameSite cookies + CORS restrictions
- SSRF → Cloud Metadata → Credential Theft → Full Account Compromise
- JWT Algorithm Confusion → Admin Token Forge → Privilege Escalation
- Path Traversal → Config Disclosure → Credentials → Account Takeover
- Open Redirect + OAuth → Token Theft via Redirect

---

## By Target Technology

### REST APIs
- Start with: [idor.md](idor.md), [rate_limit.md](rate_limit.md), [cors.md](cors.md)
- Then: [sqli.md](sqli.md) (filter/search params), [auth_bypass.md](auth_bypass.md) (API versioning)

### GraphQL APIs
- Start with: [cors.md](cors.md) (common Hasura/Apollo misconfiguration)
- Then: [sqli.md](sqli.md) (resolver injection), [idor.md](idor.md) (query by ID)
- Check: [jwt.md](jwt.md) (JWT auth on GraphQL)

### Payment / Checkout Flows
- Priority: [cors.md](cors.md), [auth_bypass.md](auth_bypass.md) (returnUrl), [jwt.md](jwt.md)
- Also: [idor.md](idor.md) (basket/order IDs), [rate_limit.md](rate_limit.md)

### Authentication Endpoints
- Priority: [rate_limit.md](rate_limit.md), [auth_bypass.md](auth_bypass.md), [jwt.md](jwt.md)
- Then: [sqli.md](sqli.md) (login SQLi), [xss.md](xss.md) (error page reflection)

### File Upload / Static Serving
- Priority: [path_traversal.md](path_traversal.md), [xss.md](xss.md) (SVG upload)
- Also: [ssrf.md](ssrf.md) (URL-based import)

### Cloud-Hosted Applications
- Priority: [ssrf.md](ssrf.md) (metadata service)
- Also: [path_traversal.md](path_traversal.md) (`.env` disclosure), [cors.md](cors.md)

---

## Program-Specific Notes

### DoorDash (HackerOne)
- **Confirmed finding:** CORS misconfiguration on `vgs-payment.doordash.com` → [cors.md#doordash](cors.md)
- **Open surface:** `identity.doordash.com` — OAuth endpoints, test redirect_uri manipulation → [auth_bypass.md](auth_bypass.md)
- **Tech:** VGS payment vault, Cloudflare WAF
- **Next to test:** SSRF on internal service APIs, IDOR on order/delivery endpoints

### Boozt Fashion AB (HackerOne)
- **Confirmed findings:**
  - CORS reflect+credentials on `kronor.io/v1/graphql` → [cors.md#boozt](cors.md) (HIGH)
  - Wildcard CORS on `payment-gateway.kronor.io` → [cors.md#boozt](cors.md)
  - Unvalidated `returnUrl` in payment flow → [auth_bypass.md#boozt](auth_bypass.md) (needs verification)
  - Hasura version disclosure → [sqli.md](sqli.md) (Hasura injection surface)
- **Tech:** Hasura GraphQL v2.37.1, Cloudflare, PHP/Symfony, GCP
- **Next to test:** GraphQL injection on Hasura endpoints, IDOR on basket/order IDs via API, JWT on Hasura auth

---

## Playbook Coverage by OWASP API Security Top 10

| OWASP API Risk | Playbook |
|---|---|
| API1:2023 — Broken Object Level Authorization | [idor.md](idor.md) |
| API2:2023 — Broken Authentication | [auth_bypass.md](auth_bypass.md), [jwt.md](jwt.md) |
| API3:2023 — Broken Object Property Level Authorization | [idor.md](idor.md) |
| API4:2023 — Unrestricted Resource Consumption | [rate_limit.md](rate_limit.md) |
| API5:2023 — Broken Function Level Authorization | [auth_bypass.md](auth_bypass.md) |
| API6:2023 — Unrestricted Access to Sensitive Business Flows | [rate_limit.md](rate_limit.md) |
| API7:2023 — Server Side Request Forgery | [ssrf.md](ssrf.md) |
| API8:2023 — Security Misconfiguration | [cors.md](cors.md), [jwt.md](jwt.md) |
| API9:2023 — Improper Inventory Management | [auth_bypass.md](auth_bypass.md) (API versioning) |
| API10:2023 — Unsafe Consumption of APIs | [ssrf.md](ssrf.md), [cors.md](cors.md) |

---

## Playbook Coverage by OWASP Web Top 10

| OWASP Web Risk | Playbook |
|---|---|
| A01:2021 — Broken Access Control | [idor.md](idor.md), [auth_bypass.md](auth_bypass.md) |
| A02:2021 — Cryptographic Failures | [jwt.md](jwt.md) |
| A03:2021 — Injection | [sqli.md](sqli.md), [xss.md](xss.md), [ssrf.md](ssrf.md) |
| A04:2021 — Insecure Design | [auth_bypass.md](auth_bypass.md) |
| A05:2021 — Security Misconfiguration | [cors.md](cors.md) |
| A07:2021 — Identification and Authentication Failures | [rate_limit.md](rate_limit.md), [auth_bypass.md](auth_bypass.md) |
| A08:2021 — Software and Data Integrity Failures | [jwt.md](jwt.md) |
| A10:2021 — Server-Side Request Forgery | [ssrf.md](ssrf.md) |

---

## Adding New Playbooks

When a new vulnerability type is discovered:

1. Create `~/BugBounty/playbooks/<vuln_type>.md` with the standard sections:
   - Overview
   - Real-world impact
   - Recon methodology
   - Testing methodology
   - Common endpoints to test
   - Payload examples
   - Automation ideas
   - Real bug bounty examples
   - Lab / Program examples

2. Add entry to this index (PLAYBOOK_INDEX.md) in all relevant tables

3. If a finding from a program matches an existing playbook, append a **Lab / Program Examples** entry to the playbook referencing the finding file

---

*All findings sourced from: `~/BugBounty/hackerone/`*
*All RedTeam lab findings sourced from: `~/RedTeam/missions/`*
