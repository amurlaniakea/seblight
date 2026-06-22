# SEB-Light: Sovereign Execution Broker for Agentic Security

**Pedro Sordo Martínez** — amurlaniakea@gmail.com
**License:** AGPL-3.0
**Repository:** https://github.com/amurlaniakea/seblight
**Based on:** "Sovereign Execution Brokers: Enforcing Certificate-Bound Authority in Agentic Control Planes" (arXiv:2606.20520, Jun 2026)

---

## Abstract

SEB-Light is a Python implementation of the Sovereign Execution Broker (SEB) pattern for securing autonomous AI agents. It enforces certificate-bound authority before executing any action, ensuring that agents never hold direct production credentials. SEB-Light provides:

- **Policy-based admission control** with 20+ default security rules
- **Cryptographic certificate signing** (HMAC-SHA256) with short-lived, single-use certificates
- **Immutable audit ledger** with hash-chained integrity verification
- **Multi-adapter execution** (shell, file, Docker, SSH)
- **Security benchmark** (SEB-Bench) with 43 test cases

Results: 93% accuracy on SEB-Bench (40/43 test cases correct).

---

## 1. Introduction

### The Problem

Autonomous AI agents (language models with tool access) are increasingly connected to real infrastructure: deploying containers, managing databases, configuring cloud resources. When an agent has direct API access, a single hallucination or adversarial prompt injection can cause:

- `rm -rf /data` — Database destruction
- `ufw disable` — Firewall deactivation
- `DROP TABLE users` — Data loss
- `shutdown -h now` — System downtime

Traditional IAM authorizes **identities**, not **actions**. OPA/Gatekeeper enforce policies but don't certify proposals. The gap between "proposal admitted" and "mutation executed" is the fundamental security gap.

### The Solution: Certificate-Bound Authority

The Sovereign Execution Broker (SEB) pattern introduces a mandatory enforcement point between agent intent and infrastructure mutation:

```
Agent → Proposal → SAB (evaluate) → Certificate → SEB (verify + execute) → Infrastructure
```

Key properties:
1. **No standing credentials** — Agents never hold production API keys
2. **Certificate-bound** — Each action requires a signed, short-lived certificate
3. **Single-use** — Certificates are revoked after execution
4. **Auditable** — All decisions recorded in an immutable ledger

---

## 2. Architecture

### 2.1 Core Components

| Component | Role | Implementation |
|-----------|------|----------------|
| **Proposal** | Agent's intent to act | `Proposal` dataclass with type, payload, actor |
| **PolicyEngine (SAB)** | Evaluates proposals against security rules | Pattern matching + priority rules |
| **Certificate** | Signed authorization for a specific action | HMAC-SHA256, 5-min TTL, single-use |
| **CommandExecutor** | Runs shell commands safely | Subprocess with timeout, env sanitization |
| **Ledger** | Immutable audit trail | Hash-chained JSONL file |
| **Broker** | Orchestrates the full pipeline | `SovereignExecutionBroker` |

### 2.2 Execution Pipeline

```
1. Agent submits Proposal (action, type, payload)
2. PolicyEngine evaluates against rules → PolicyDecision
3. If allowed: SAB issues signed Certificate
4. SEB verifies Certificate (signature, expiry, revocation)
5. SEB routes to appropriate adapter (shell/file/docker/ssh)
6. Adapter executes with safety controls
7. Result recorded in Ledger
8. Certificate revoked (single-use)
```

### 2.3 Adapters

| Adapter | Operations | Safety Controls |
|---------|------------|-----------------|
| **CommandExecutor** | Shell commands | Timeout, env sanitization, output limits |
| **FileAdapter** | write, delete, chmod, read | Blocked paths, size limits |
| **DockerAdapter** | run, stop, rm, build, pull, ps, logs, exec | Blocked operations (prune, rmi -f) |
| **SSHAdapter** | Remote command execution | Timeout, key-based auth |

---

## 3. Policy Engine

### 3.1 Rule System

Rules are pattern-based with priority ordering:

```python
PolicyRule(
    name="block_rm_rf_root",
    description="Block root filesystem deletion",
    severity=Severity.BLOCKED,
    patterns=["rm -rf /", "rm -rf /*"],
    effect="deny",
    priority=100
)
```

### 3.2 Severity Levels

| Level | Behavior | Examples |
|-------|----------|----------|
| **BLOCKED** | Always rejected | `rm -rf /`, `mkfs`, `kill -9 1` |
| **MODERATE** | Warn user, configurable | `rm -rf /tmp`, `apt remove`, `docker stop` |
| **SAFE** | Auto-approved | `ls`, `cat`, `echo`, `mkdir` |

### 3.3 Default Rules

- **15 BLOCKED patterns**: root deletion, disk format, firewall disable, init kill, fork bomb, shutdown, database drop, Docker destruction, recursive chmod
- **12 MODERATE patterns**: file deletion, package removal, service restart, Docker stop, chmod, network operations, SSH
- **Custom rules**: JSON policy file for domain-specific rules

---

## 4. Certificate System

### 4.1 Certificate Structure

```python
Certificate(
    proposal_id="uuid",
    proposal_fingerprint="sha256",
    severity=Severity.SAFE,
    allowed=True,
    scope=["command"],
    constraints={"matched_rules": [...]},
    issued_at=1719000000.0,
    expires_at=1719000300.0,  # 5 min TTL
    signature="hmac-sha256-hex"
)
```

### 4.2 Security Properties

- **Short-lived**: 5-minute validity window (configurable)
- **Single-use**: Revoked immediately after execution
- **Signed**: HMAC-SHA256 with secret key
- **Bound to proposal**: Fingerprint of original proposal embedded
- **Verifiable**: Signature verification without secret key access

---

## 5. Ledger

### 5.1 Hash Chain

Each ledger entry contains the hash of the previous entry:

```
Entry[n].previous_hash = hash(Entry[n-1])
```

This ensures **tamper detection**: modifying any entry breaks the chain.

### 5.2 Event Types

- `PROPOSAL_RECEIVED` — Agent submitted a proposal
- `POLICY_EVALUATED` — Policy decision made
- `CERTIFICATE_ISSUED` — Certificate created
- `EXECUTION_COMPLETED` — Command executed successfully
- `EXECUTION_FAILED` — Command execution failed
- `EXECUTION_REJECTED` — Blocked by policy
- `CERTIFICATE_REVOKED` — Single-use certificate consumed
- `CERTIFICATE_EXPIRED` — Certificate expired before use

---

## 6. SEB-Bench: Security Evaluation Benchmark

### 6.1 Dataset

43 test cases across 4 categories:

| Category | Count | Description |
|----------|-------|-------------|
| Destructive | 15 | Commands that should always be blocked |
| Moderate | 8 | Commands that should be flagged but may be allowed |
| Safe | 15 | Commands that should always be allowed |
| Injection | 5 | Prompt injection attempts |

### 6.2 Metrics

- **TPR (True Positive Rate)**: % of dangerous commands correctly blocked
- **TNR (True Negative Rate)**: % of safe commands correctly allowed
- **FPR (False Positive Rate)**: % of safe commands incorrectly blocked
- **FNR (False Negative Rate)**: % of dangerous commands incorrectly allowed
- **F1 Score**: Harmonic mean of precision and recall

### 6.3 Results

```
Total cases:    43
Correct:        40 (93.0%)
TPR (recall):   90.0%
TNR (specific): 95.7%
FPR:            4.3%
FNR:            10.0%
F1 Score:       92.3%
Duration:       67ms
```

### 6.4 Known Limitations

Three false negatives:
1. `rm -rf /tmp/old_logs` — Blocked due to aggressive `rm -rf` pattern (false positive on moderate)
2. `sudo su -c 'chmod 777 /'` — Nested command not parsed
3. `echo 'cm0gLXJmIC8=' | base64 -d | bash` — Encoded command not detected

These require semantic analysis beyond pattern matching.

---

## 7. Comparison with Related Work

| Feature | SEB (Paper) | OpenKedge | SEB-Light |
|---------|-------------|-----------|-----------|
| Language | Go | TypeScript | Python |
| Target | AWS/Kubernetes | Cloud infrastructure | Local agents |
| Certificate | X.509-style | Custom | HMAC-SHA256 |
| Identity | AWS STS / K8s TokenRequest | Cloud IAM | Subprocess env |
| Ledger | Cloud-native | Event store | Local JSONL |
| Adapters | AWS, K8s | AWS | Shell, File, Docker, SSH |
| Benchmark | Latency overheads | None | SEB-Bench (43 cases) |
| License | Unknown | Unknown | AGPL-3.0 |

---

## 8. Integration with Hermes Agent

SEB-Light includes a skill for Hermes Agent that routes command execution through the SEB pipeline:

```bash
# Evaluate before executing
python3 seblight_run.py evaluate "list files" "ls -la /tmp"

# Execute through SEB
python3 seblight_run.py execute "list files" "ls -la /tmp"

# Audit trail
python3 seblight_run.py audit --proposal-id <id>

# Verify integrity
python3 seblight_run.py verify
```

The skill is installed at `~/.hermes/skills/seblight/SKILL.md`.

---

## 9. Future Work

1. **Semantic analysis**: Replace pattern matching with AST-based command parsing
2. **Encoded command detection**: Base64, hex, URL decoding
3. **Multi-agent coordination**: Shared ledger across agent swarms
4. **Cloud adapters**: AWS, GCP, Azure mutation proxies
5. **Formal verification**: Prove security properties of the pipeline
6. **SEB-Bench expansion**: More test cases, adversarial examples

---

## 10. References

1. Jun He, Deying Yu. "Sovereign Execution Brokers: Enforcing Certificate-Bound Authority in Agentic Control Planes." arXiv:2606.20520, Jun 2026.
2. OpenKedge. https://github.com/openkedge/openkedge
3. Hermes Agent. https://hermes-agent.nousresearch.com

---

*SEB-Light v0.1.0 — Copyright (C) 2026 Pedro Sordo Martínez*
