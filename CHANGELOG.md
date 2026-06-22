# Changelog

All notable changes to SEB-Light will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-22

### Added
- Policy Engine (SAB) — Block/Allow/Moderate rules with pattern matching
- Certificate Manager — HMAC-SHA256 signed, short-lived, single-use certificates
- Command Executor — Subprocess execution with sanitized environment
- Ledger — Hash-chained immutable audit log
- CLI — `seblight_run.py evaluate`, `execute`, `audit`, `verify`, `stats`
- 31 tests
- pyproject.toml (package is now pip-installable)
- Makefile with standard targets
- ruff, mypy, black configuration
- Coverage configuration (minimum 80%)
- SECURITY.md and CHANGELOG.md
- CI/CD via GitHub Actions (Python 3.10, 3.11, 3.12)

### Cleanup
- Removed dead `repomapper.py` code (782 lines, not imported anywhere)
- Added .gitignore for Python artifacts

### Policy Rules

**BLOCKED (always rejected):**
- `rm -rf /`, `rm -rf /*` — root deletion
- `mkfs`, `dd if=/dev/zero of=/dev/` — disk destruction
- `chmod -R 777 /` — permission destruction
- `> /etc/passwd`, `> /etc/shadow` — system file overwrite
- `iptables -F`, `ufw disable` — firewall disable
- `systemctl stop/disable` — service stop
- `shutdown`, `reboot`, `poweroff` — system shutdown
- Fork bomb patterns

**MODERATE (warn user):** rm, chmod, chown, apt remove, pip uninstall, docker stop, curl, wget, nc

**SAFE (auto-approved):** ls, cat, grep, find, ps, df, echo, printf, mkdir, touch
