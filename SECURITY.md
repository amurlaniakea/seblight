# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.0   | Yes       |

## Reporting a Security Vulnerability

If you discover a security vulnerability in SEB-Light, please report it responsibly.

**Do NOT open a public GitHub Issue for security vulnerabilities.**

Instead, report via email:
- **Email:** amurlaniakea@gmail.com
- **Subject:** `[SECURITY] SEB-Light vulnerability`

You will receive a response within 48 hours.

## Security Considerations

SEB-Light enforces certificate-bound authority before executing shell commands:

- **Policy Engine (SAB):** Blocklist covers common destructive commands but may not cover all attack vectors. Custom policies should be added for domain-specific threats.
- **Certificate:** HMAC-SHA256 signed, short-lived, single-use. Compromised signing keys break the trust model.
- **Ledger:** Hash-chained immutable audit log. Ledger file should be stored in a tamper-evident location.
- **Command Execution:** Subprocess with sanitized environment. Does not protect against all side-channel attacks.

**SEB-Light is a defense-in-depth layer, not a complete security solution.**

## Dependencies

No runtime dependencies (Python stdlib only).
Dev: `pytest`, `pytest-cov`, `black`, `ruff`, `mypy`
