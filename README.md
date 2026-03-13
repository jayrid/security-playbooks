# security-playbooks 📓📖

### Overview
This repository contains repeatable penetration testing methodologies and vulnerability assessment playbooks. It is designed to provide a structured approach to identifying, testing, and documenting security vulnerabilities across various domains including web, API, and authentication systems.

### Repository Structure
- **`web/`**: Web application security testing playbooks (SQLi, XSS, SSRF, IDOR).
- **`api/`**: Security assessment playbooks for REST and GraphQL APIs.
- **`authentication/`**: Methodologies for testing auth bypasses, JWT vulnerabilities, and MFA research.
- **`privilege-escalation/`**: Playbooks for system-level privilege escalation techniques.
- **`blueteam/`**: Defensive strategy and incident response playbooks.

### Example Usage
To reference the SQL injection testing methodology:
```bash
cat web/sqli.md
```
To implement a structured API security assessment:
```bash
cat api/rate_limit.md
```

### Future Roadmap
- Mapping all playbooks to OWASP ASVS and API Security Top 10 (2023).
- Automated generation of test checklists for specific engagement types.
- Development of specialized playbooks for Kubernetes and cloud infrastructure security.
- Addition of custom Burp Suite configurations for each testing methodology.
