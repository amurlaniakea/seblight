# SEB-Light

**Sovereign Execution Broker (Python implementation)**

Enforces certificate-bound authority before executing any shell command. Based on the paper ["Sovereign Execution Brokers: Enforcing Certificate-Bound Authority in Agentic Control Planes"](https://arxiv.org/abs/2606.20520) (arXiv:2606.20520, Jun 2026).

## The Problem

When an autonomous AI agent has direct access credentials to production infrastructure, a single hallucination or prompt injection can cause:
- Database deletion
- Public port exposure
- Critical infrastructure termination

Traditional IAM authorizes **identities**, not **certified actions**. SEB-Light closes this gap.

## Architecture

```
Agent Proposal → PolicyEngine (SAB) → Certificate → CommandExecutor → Ledger
                     ↓                    ↓              ↓
               Evaluate rules      HMAC-signed      Hash-chained
               Block/Allow/Mod     Short-lived      Immutable audit
```

**Pipeline:**
1. Agent submits a **Proposal** (what it wants to execute)
2. **PolicyEngine (SAB)** evaluates against security rules
3. If approved, a signed **Certificate** is issued (short-lived, single-use)
4. **CommandExecutor** runs the command with sanitized environment
5. **Ledger** records everything in a hash-chained, immutable log
6. Certificate is revoked after execution

## Quick Start

```bash
# Clone
git clone https://github.com/amurlaniakea/seblight.git
cd seblight

# Setup
python3 -m venv venv
source venv/bin/activate
pip install -e .

# Evaluate a command (dry run)
python3 seblight_run.py evaluate "list files" "ls -la /tmp"
# → {"allowed": true, "severity": "safe"}

# Execute through SEB
python3 seblight_run.py execute "echo test" "echo SEB-Light works!"
# → {"status": "executed", "certificate_id": "...", "execution": {...}}

# Verify ledger integrity
python3 seblight_run.py verify
# → ✅ Ledger integrity: VALID

# Run tests
pytest tests/ -v
# → 31 passed
```

## Policy Rules

### BLOCKED (always rejected)
- `rm -rf /`, `rm -rf /*` — root deletion
- `mkfs`, `dd if=/dev/zero of=/dev/` — disk destruction
- `chmod -R 777 /` — permission destruction
- `> /etc/passwd`, `> /etc/shadow` — system file overwrite
- `iptables -F`, `ufw disable` — firewall disable
- `systemctl stop/disable` — service stop
- `shutdown`, `reboot`, `poweroff` — system shutdown
- Fork bomb patterns

### MODERATE (warn user)
- `rm -rf`, `rm -r`, `rm` — deletion
- `chmod`, `chown` — permission changes
- `apt remove/purge`, `pip uninstall` — package removal
- `docker stop/kill` — container stop
- `curl`, `wget`, `nc` — network operations

### SAFE (auto-approved)
- `ls`, `cat`, `grep`, `find`, `ps`, `df` — read-only
- `echo`, `printf` — output
- `mkdir`, `touch` — safe file creation

## Custom Policies

Create a JSON policy file:

```json
{
  "rules": [
    {
      "name": "block_production_db",
      "description": "Block access to production database",
      "severity": "blocked",
      "patterns": ["prod-db", "production-database"],
      "action_types": ["command"],
      "effect": "deny",
      "priority": 200
    }
  ]
}
```

## Project Structure

```
seblight/
├── seblight/
│   ├── __init__.py
│   ├── core/
│   │   ├── models.py       # Proposal, Certificate, PolicyDecision, etc.
│   │   ├── policy.py       # PolicyEngine (SAB) + PolicyRule
│   │   ├── executor.py     # CommandExecutor
│   │   ├── ledger.py       # Immutable hash-chained ledger
│   │   └── broker.py       # SovereignExecutionBroker
│   ├── cli/
│   │   └── main.py         # CLI interface
│   └── adapters/           # (future: Docker, SSH, etc.)
├── tests/
│   └── test_seblight.py    # 31 tests
├── seblight_run.py         # Hermes integration wrapper
├── venv/
└── README.md
```

## Integration with Hermes Agent

SEB-Light includes a skill for [Hermes Agent](https://hermes-agent.nousresearch.com):

```bash
# Skill location
~/.hermes/skills/seblight/SKILL.md

# Wrapper
python3 /home/sil/seblight/seblight_run.py evaluate "action" "command"
python3 /home/sil/seblight/seblight_run.py execute "action" "command"
```

## Differences from the Paper

| Feature | Paper (Go) | SEB-Light (Python) |
|---------|------------|---------------------|
| Target | AWS/Kubernetes | Local agents (Hermes/Tars) |
| Language | Go | Python |
| Certificate | X.509-style | HMAC-SHA256 |
| Identity | AWS STS / K8s TokenRequest | Subprocess env sanitization |
| Ledger | Cloud-native | Local JSONL file |
| Focus | Cloud infrastructure | Agent command execution |

## License

MIT

## References

- [Sovereign Execution Brokers (arXiv:2606.20520)](https://arxiv.org/abs/2606.20520)
- [OpenKedge](https://github.com/openkedge/openkedge) — Reference implementation in TypeScript
