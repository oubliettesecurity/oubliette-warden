# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | Yes                |
| < 0.2   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in Oubliette Warden, please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities.
2. Email security findings to: **security@oubliettesecurity.com**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues. We will coordinate disclosure timing with the reporter.

## Scope

Oubliette Warden is designed for **authorized security testing** only. It can drive real offensive tooling (nmap, Metasploit auxiliary scanners), and its safety gate is meant to fail closed.

**In scope:**
- Any way to get a command APPROVEd or executed without plan attribution, outside the human-approved plan, or outside the declared target scope (bypasses of the safety gate or the `plan_consistency` verifier)
- Argument/target validation bypasses in the nmap or Metasploit adapters
- Authentication or authorization bypasses in the operator review/audit API
- Information disclosure through the audit log, API responses, error messages, or logs

**Out of scope:**
- Vulnerabilities in target systems being tested (report those to the target's maintainers)
- Vulnerabilities in third-party tools Warden drives or integrates with (nmap, Metasploit, MITRE CALDERA, Qdrant, Ollama); please report those upstream
- Use of Warden against systems you are not authorized to test
- Social engineering of Oubliette Security staff

## Security Best Practices

When using Oubliette Warden:

- Only run it against systems you own or are explicitly authorized to assess
- Keep the operator API bound to localhost (the default) and set `OUBLIETTE_WARDEN_API_KEYS`; without keys, protected routes fail closed with 401
- Review every plan before approving it; `oubliette-warden gate` shows the decision without executing anything
- Treat plan files and audit logs as sensitive (they contain targets and command lines)
