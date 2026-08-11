# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
SEB-Light: Tests

Run with: pytest tests/ -v
"""

import json
import time
import pytest

from seblight.core.broker import BrokerConfig, SovereignExecutionBroker
from seblight.core.ledger import Ledger
from seblight.core.models import (
    Certificate,
    ExecutionResult,
    ExecutionStatus,
    LedgerEntry,
    PolicyDecision,
    Proposal,
    ProposalType,
    Severity,
)
from seblight.core.policy import PolicyEngine, PolicyRule


# ==========================================
# Models Tests
# ==========================================


class TestProposal:
    def test_create_proposal(self):
        p = Proposal(
            action="list files",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "ls -la"},
            actor="test",
        )
        assert p.action == "list files"
        assert p.proposal_type == ProposalType.COMMAND
        assert p.actor == "test"
        assert p.id is not None

    def test_fingerprint_consistency(self):
        p = Proposal(
            action="test",
            proposal_type=ProposalType.COMMAND,
            payload={"cmd": "echo hi"},
            actor="test",
        )
        fp1 = p.fingerprint()
        fp2 = p.fingerprint()
        assert fp1 == fp2

    def test_fingerprint_uniqueness(self):
        p1 = Proposal(action="a", proposal_type=ProposalType.COMMAND, payload={"x": "1"}, actor="t")
        p2 = Proposal(action="b", proposal_type=ProposalType.COMMAND, payload={"x": "2"}, actor="t")
        assert p1.fingerprint() != p2.fingerprint()

    def test_to_dict(self):
        p = Proposal(action="test", proposal_type=ProposalType.COMMAND, payload={"x": "1"}, actor="t")
        d = p.to_dict()
        assert d["action"] == "test"
        assert d["proposal_type"] == "command"


class TestCertificate:
    def test_create_certificate(self):
        cert = Certificate(
            proposal_id="p1",
            proposal_fingerprint="fp1",
            severity=Severity.SAFE,
            allowed=True,
            scope=["command"],
        )
        assert cert.proposal_id == "p1"
        assert cert.allowed is True
        assert cert.is_valid is False  # No signature yet

    def test_expiration(self):
        cert = Certificate(
            proposal_id="p1",
            proposal_fingerprint="fp1",
            severity=Severity.SAFE,
            allowed=True,
            scope=["command"],
            issued_at=time.time() - 600,
            expires_at=time.time() - 300,  # Expired 5 min ago
        )
        assert cert.is_expired is True

    def test_not_expired(self):
        cert = Certificate(
            proposal_id="p1",
            proposal_fingerprint="fp1",
            severity=Severity.SAFE,
            allowed=True,
            scope=["command"],
            expires_at=time.time() + 300,
        )
        assert cert.is_expired is False


class TestLedgerEntry:
    def test_hash_consistency(self):
        e = LedgerEntry(event_type="TEST", timestamp=1.0, proposal_id="p1")
        assert e.hash("test-key") == e.hash("test-key")

    def test_hash_uniqueness(self):
        e1 = LedgerEntry(event_type="TEST1", timestamp=1.0, proposal_id="p1")
        e2 = LedgerEntry(event_type="TEST2", timestamp=2.0, proposal_id="p2")
        assert e1.hash("test-key") != e2.hash("test-key")

    def test_hash_is_keyed_hmac(self):
        """Same entry hashed with different keys must differ (HMAC, not plain SHA-256)."""
        e = LedgerEntry(event_type="TEST", timestamp=1.0, proposal_id="p1")
        assert e.hash("key-a") != e.hash("key-b")


# ==========================================
# Policy Engine Tests
# ==========================================


class TestPolicyEngine:
    def setup_method(self):
        self.engine = PolicyEngine()

    def test_safe_command(self):
        p = Proposal(
            action="list files",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "ls -la /home"},
            actor="test",
        )
        decision = self.engine.evaluate(p)
        assert decision.allowed is True
        assert decision.severity == Severity.SAFE

    def test_blocked_rm_rf(self):
        p = Proposal(
            action="delete everything",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "rm -rf /"},
            actor="test",
        )
        decision = self.engine.evaluate(p)
        assert decision.allowed is False
        assert decision.severity == Severity.BLOCKED

    def test_moderate_rm(self):
        p = Proposal(
            action="remove dir",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "rm /tmp/old_file.txt"},
            actor="test",
        )
        decision = self.engine.evaluate(p)
        assert decision.severity == Severity.MODERATE

    def test_issue_certificate(self):
        p = Proposal(
            action="safe command",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "echo hello"},
            actor="test",
        )
        decision = self.engine.evaluate(p)
        cert = self.engine.issue_certificate(p, decision)
        assert cert.proposal_id == p.id
        assert cert.allowed is True
        assert cert.signature != ""
        assert self.engine.verify_certificate(cert) is True

    def test_reject_certificate_for_blocked(self):
        p = Proposal(
            action="dangerous",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "rm -rf /"},
            actor="test",
        )
        decision = self.engine.evaluate(p)
        cert = self.engine.issue_certificate(p, decision)
        assert cert.allowed is False

    def test_custom_rule(self):
        engine = PolicyEngine()
        engine.rules.append(PolicyRule(
            name="block_secret",
            description="Block access to secrets",
            severity=Severity.BLOCKED,
            patterns=["/etc/shadow", "/.ssh/"],
            priority=200,
        ))
        engine.rules.sort(key=lambda r: r.priority, reverse=True)

        p = Proposal(
            action="read shadow",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "cat /etc/shadow"},
            actor="test",
        )
        decision = engine.evaluate(p)
        assert decision.allowed is False
        assert "block_secret" in decision.matched_rules

    # --- Auditoría 2026-08-11: bypass por substring matching (PoC T1) ---
    # Estos 3 casos son PERMANENTES: nunca deben volver a ser SAFE.

    def test_double_space_rm_rf_blocked(self):
        """'rm  -rf /' (doble espacio) debe salir BLOCKED, no MODERATE/SAFE."""
        p = Proposal(
            action="delete everything",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "rm  -rf /"},
            actor="test",
        )
        decision = self.engine.evaluate(p)
        assert decision.severity == Severity.BLOCKED
        assert decision.allowed is False

    def test_variable_indirection_rm_rf_blocked(self):
        """'X=rm; $X -rf /' (indirección de variable) debe salir BLOCKED."""
        p = Proposal(
            action="delete everything",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "X=rm; $X -rf /"},
            actor="test",
        )
        decision = self.engine.evaluate(p)
        assert decision.severity == Severity.BLOCKED
        assert decision.allowed is False

    def test_base64_encoded_rm_rf_blocked(self):
        """'echo cm0gLXJmIC8= | base64 -d | bash' (rm -rf / codificado) debe
        salir BLOCKED o MODERATE, nunca SAFE (fail-closed)."""
        p = Proposal(
            action="delete everything",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "echo cm0gLXJmIC8= | base64 -d | bash"},
            actor="test",
        )
        decision = self.engine.evaluate(p)
        assert decision.severity in (Severity.BLOCKED, Severity.MODERATE)
        assert decision.severity != Severity.SAFE
        assert decision.allowed is False


# ==========================================
# Command Executor Tests
# ==========================================


class TestCommandExecutor:
    def test_execute_simple_command(self):
        from seblight.core.executor import CommandExecutor
        executor = CommandExecutor()
        p = Proposal(
            action="echo test",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "echo hello world"},
            actor="test",
        )
        result = executor.execute(p, certificate_id="test-cert")
        assert result.success is True
        assert "hello world" in result.output
        assert result.exit_code == 0

    def test_execute_failure(self):
        from seblight.core.executor import CommandExecutor
        executor = CommandExecutor()
        p = Proposal(
            action="fail",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "exit 42"},
            actor="test",
        )
        result = executor.execute(p, certificate_id="test-cert")
        assert result.success is False
        assert result.exit_code == 42

    def test_timeout(self):
        from seblight.core.executor import CommandExecutor
        executor = CommandExecutor(default_timeout=2)
        p = Proposal(
            action="sleep",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "sleep 10", "timeout": 1},
            actor="test",
        )
        result = executor.execute(p, certificate_id="test-cert")
        assert result.success is False
        assert "timed out" in result.error.lower()

    def test_dry_run(self):
        from seblight.core.executor import CommandExecutor
        executor = CommandExecutor()
        p = Proposal(
            action="dry run",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "rm -rf /important"},
            actor="test",
        )
        result = executor.execute(p, certificate_id="test-cert", dry_run=True)
        assert result.success is True
        assert "DRY RUN" in result.output

    def test_no_command(self):
        from seblight.core.executor import CommandExecutor
        executor = CommandExecutor()
        p = Proposal(action="empty", proposal_type=ProposalType.COMMAND, payload={}, actor="test")
        result = executor.execute(p, certificate_id="test-cert")
        assert result.success is False
        assert "No command" in result.error


# ==========================================
# Ledger Tests
# ==========================================


class TestLedger:
    def test_requires_secret_key(self):
        """Fail closed: a ledger without a key must refuse to start."""
        with pytest.raises(ValueError):
            Ledger()

    def test_append(self):
        ledger = Ledger(secret_key="test-key")
        entry = ledger.append("TEST", "p1", {"key": "value"})
        assert ledger.size == 1
        assert entry.event_type == "TEST"

    def test_chain_integrity(self):
        ledger = Ledger(secret_key="test-key")
        ledger.append("STEP1", "p1")
        ledger.append("STEP2", "p1")
        ledger.append("STEP3", "p2")
        valid, broken = ledger.verify_integrity()
        assert valid is True
        assert broken is None

    def test_chain_broken(self):
        ledger = Ledger(secret_key="test-key")
        e1 = ledger.append("STEP1", "p1")
        e2 = ledger.append("STEP2", "p1")
        # Tamper with the chain
        e2.previous_hash = "tampered"
        valid, broken = ledger.verify_integrity()
        assert valid is False

    def test_wrong_key_breaks_chain(self, tmp_path):
        """Reloading the same log with a different key must fail verification."""
        log_file = str(tmp_path / "ledger.jsonl")
        ledger = Ledger(log_file=log_file, secret_key="real-key")
        ledger.append("STEP1", "p1")
        ledger.append("STEP2", "p1")

        ledger2 = Ledger(log_file=log_file, secret_key="wrong-key")
        valid, broken = ledger2.verify_integrity()
        assert valid is False
        assert broken is not None

    def test_tampered_jsonl_detected_with_hmac(self, tmp_path):
        """PoC T3: tamper a .jsonl line + naive sha256 chain recomputation
        (attacker without the key) must still fail verify_integrity()."""
        import hashlib

        log_file = str(tmp_path / "ledger.jsonl")
        key = "correct-secret"
        ledger = Ledger(log_file=log_file, secret_key=key)
        ledger.append("STEP1", "p1")
        ledger.append("STEP2", "p1")
        ledger.append("STEP3", "p2")

        # Attacker rewrites entry B (details) and recomputes the chain NAIVELY
        # with plain SHA-256 (they don't know the HMAC key).
        lines = open(log_file).read().splitlines()
        a = json.loads(lines[0])
        b = json.loads(lines[1])
        c = json.loads(lines[2])

        b["details"]["evil"] = True

        def naive_sha256(d: dict) -> str:
            payload = json.dumps({
                "id": d["id"],
                "event_type": d["event_type"],
                "timestamp": d["timestamp"],
                "proposal_id": d["proposal_id"],
                "certificate_id": d["certificate_id"],
                "details": d["details"],
                "previous_hash": d["previous_hash"],
            }, sort_keys=True)
            return hashlib.sha256(payload.encode()).hexdigest()

        b["previous_hash"] = naive_sha256(a)
        c["previous_hash"] = naive_sha256(b)

        with open(log_file, "w") as f:
            f.write("\n".join(json.dumps(x) for x in (a, b, c)) + "\n")

        # Reload with the CORRECT key: the naive sha256 chain must NOT verify.
        ledger2 = Ledger(log_file=log_file, secret_key=key)
        valid, broken = ledger2.verify_integrity()
        assert valid is False
        assert broken is not None

    def test_get_entries_for_proposal(self):
        ledger = Ledger(secret_key="test-key")
        ledger.append("E1", "p1")
        ledger.append("E2", "p2")
        ledger.append("E3", "p1")
        entries = ledger.get_entries_for_proposal("p1")
        assert len(entries) == 2

    def test_export_json(self):
        ledger = Ledger(secret_key="test-key")
        ledger.append("TEST", "p1", {"action": "test"})
        json_str = ledger.export_json("p1")
        data = json.loads(json_str)
        assert len(data) == 1
        assert data[0]["event_type"] == "TEST"


# ==========================================
# Broker Integration Tests
# ==========================================


class TestSovereignExecutionBroker:
    def setup_method(self):
        self.config = BrokerConfig(dry_run=True, secret_key="test-secret-key")
        self.broker = SovereignExecutionBroker(self.config)

    def test_safe_proposal_flow(self):
        p = Proposal(
            action="list files",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "ls -la"},
            actor="test",
        )
        result = self.broker.process_proposal(p)
        assert result["status"] == ExecutionStatus.EXECUTED.value
        assert result["policy_decision"]["allowed"] is True

    def test_blocked_proposal_flow(self):
        p = Proposal(
            action="delete root",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "rm -rf /"},
            actor="test",
        )
        result = self.broker.process_proposal(p)
        assert result["status"] == ExecutionStatus.REJECTED.value
        assert result["policy_decision"]["allowed"] is False

    def test_ledger_entries_created(self):
        p = Proposal(
            action="test flow",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "echo test"},
            actor="test",
        )
        self.broker.process_proposal(p)
        entries = self.broker.ledger.get_entries_for_proposal(p.id)
        assert len(entries) >= 4  # proposal, policy, cert issued, cert revoked

    def test_ledger_integrity(self):
        for i in range(5):
            p = Proposal(
                action=f"test {i}",
                proposal_type=ProposalType.COMMAND,
                payload={"command": f"echo {i}"},
                actor="test",
            )
            self.broker.process_proposal(p)
        valid, broken = self.broker.verify_ledger_integrity()
        assert valid is True

    def test_stats(self):
        stats = self.broker.stats
        assert "total_entries" in stats
        assert "ledger_integrity" in stats
        assert stats["ledger_integrity"] is True

    def test_with_real_execution(self):
        config = BrokerConfig(dry_run=False, secret_key="test-secret-key")
        broker = SovereignExecutionBroker(config)
        p = Proposal(
            action="echo hello",
            proposal_type=ProposalType.COMMAND,
            payload={"command": "echo seblight works"},
            actor="test",
        )
        result = broker.process_proposal(p)
        assert result["status"] == ExecutionStatus.EXECUTED.value
        assert "seblight works" in result["execution"]["output"]


# ==========================================
# Run with: pytest tests/ -v
# ==========================================
