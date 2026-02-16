# Security Policy

## Reporting a Vulnerability

g0 is a security assessment tool, and we take security seriously.

If you discover a security vulnerability in g0 itself, please report it responsibly:

**Email:** security@guard0.ai

**Do NOT:**
- Open a public GitHub issue for security vulnerabilities
- Share details publicly before the issue is resolved

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 5 business days
- **Fix timeline:** Depends on severity, typically within 30 days for critical issues

## Scope

The following are in scope:
- Vulnerabilities in g0 CLI code
- Supply chain issues in g0 dependencies
- Issues that could cause g0 to produce misleading security assessments (false negatives)
- Guard0 Cloud/Platform vulnerabilities

The following are out of scope:
- Security findings in test fixtures (these are intentionally vulnerable)
- Issues in user-provided custom rules
- Social engineering attacks

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| < Latest | Best effort |

## Recognition

We appreciate responsible disclosure and will credit reporters in our changelog (unless you prefer to remain anonymous).
