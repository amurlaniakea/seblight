"""
SEB-Light: Sovereign Execution Broker

The main broker that orchestrates the SEB pipeline:
  Proposal → Evaluate → Certificate → Execute → Verify → Ledger

Based on: "Sovereign Execution Brokers: Enforcing Certificate-Bound Authority
          in Agentic Control Planes" (arXiv:2606.20520, Jun 2026)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .executor import CommandExecutor
from .ledger import Ledger
from .models import (
    Certificate,
    ExecutionResult,
    ExecutionStatus,
    LedgerEntry,
    PolicyDecision,
    Proposal,
    ProposalType,
    Severity,
)
from .policy import PolicyEngine

# Import adapters
from ..adapters import DockerAdapter, FileAdapter, SSHAdapter


@dataclass
class BrokerConfig:
    """Configuration for the SEB."""
    # Policy settings
    policy_file: str | None = None
    secret_key: str | None = None

    # Execution settings
    default_timeout: int = 30
    max_output_bytes: int = 1_000_000

    # Certificate settings
    cert_validity_seconds: int = 300  # 5 minutes

    # Ledger settings
    ledger_file: str | None = None

    # Safety settings
    dry_run: bool = False
    require_approval_for_moderate: bool = True
    auto_execute_safe: bool = True


class SovereignExecutionBroker:
    """
    The main SEB that enforces certificate-bound authority.

    Pipeline:
    1. Agent submits a Proposal
    2. SAB (PolicyEngine) evaluates the proposal
    3. If approved, SAB issues a signed Certificate
    4. SEB verifies the Certificate
    5. SEB executes the action (via CommandExecutor)
    6. SEB records everything in the Ledger
    """

    def __init__(self, config: BrokerConfig | None = None):
        self.config = config or BrokerConfig()

        # Initialize components
        self.policy_engine = PolicyEngine(
            secret_key=self.config.secret_key,
            policy_file=self.config.policy_file,
        )
        self.executor = CommandExecutor(
            default_timeout=self.config.default_timeout,
            max_output_bytes=self.config.max_output_bytes,
        )
        self.ledger = Ledger(log_file=self.config.ledger_file)

        # Initialize adapters
        self.file_adapter = FileAdapter()
        self.docker_adapter = DockerAdapter()
        self.ssh_adapter = SSHAdapter()

        # Track active certificates
        self._active_certificates: dict[str, Certificate] = {}

    def process_proposal(self, proposal: Proposal) -> dict[str, Any]:
        """
        Process a proposal through the full SEB pipeline.
        Returns a result dict with all steps.
        """
        result = {
            "proposal_id": proposal.id,
            "action": proposal.action,
            "status": ExecutionStatus.PENDING.value,
            "steps": [],
        }

        # Step 1: Log proposal received
        self.ledger.append(
            event_type="PROPOSAL_RECEIVED",
            proposal_id=proposal.id,
            details={"action": proposal.action, "type": proposal.proposal_type.value},
        )
        result["steps"].append("1. Proposal received and logged")

        # Step 2: Evaluate against policies
        decision = self.policy_engine.evaluate(proposal)
        self.ledger.append(
            event_type="POLICY_EVALUATED",
            proposal_id=proposal.id,
            details={
                "allowed": decision.allowed,
                "severity": decision.severity.value,
                "reasons": decision.reasons,
                "matched_rules": decision.matched_rules,
            },
        )
        result["steps"].append(f"2. Policy evaluation: {decision.severity.value} — {'ALLOWED' if decision.allowed else 'BLOCKED'}")
        result["policy_decision"] = {
            "allowed": decision.allowed,
            "severity": decision.severity.value,
            "reasons": decision.reasons,
            "matched_rules": decision.matched_rules,
        }

        # Step 3: Issue certificate
        cert = self.policy_engine.issue_certificate(proposal, decision)
        self._active_certificates[cert.id] = cert
        self.ledger.append(
            event_type="CERTIFICATE_ISSUED",
            proposal_id=proposal.id,
            certificate_id=cert.id,
            details={
                "allowed": cert.allowed,
                "severity": cert.severity.value,
                "expires_at": cert.expires_at,
                "signature": cert.signature[:16] + "...",
            },
        )
        result["steps"].append(f"3. Certificate issued: {cert.id[:8]}...")
        result["certificate_id"] = cert.id

        # Step 4: Check if execution is needed
        if not cert.allowed:
            result["status"] = ExecutionStatus.REJECTED.value
            result["steps"].append("4. REJECTED — Certificate not allowed")
            self.ledger.append(
                event_type="EXECUTION_REJECTED",
                proposal_id=proposal.id,
                certificate_id=cert.id,
                details={"reason": "Certificate not allowed by policy"},
            )
            return result

        if cert.is_expired:
            result["status"] = ExecutionStatus.REVOKED.value
            result["steps"].append("4. REVOKED — Certificate expired")
            self.ledger.append(
                event_type="CERTIFICATE_EXPIRED",
                proposal_id=proposal.id,
                certificate_id=cert.id,
            )
            return result

        # Step 5: Execute via appropriate adapter
        if self.config.dry_run:
            result["steps"].append("5. DRY RUN — Execution skipped")
            exec_result = ExecutionResult(
                success=True,
                certificate_id=cert.id,
                proposal_id=proposal.id,
                output="[DRY RUN] Action would be executed here",
            )
        else:
            exec_result = self._execute_via_adapter(proposal, cert.id)
            result["steps"].append(f"5. Executed via {proposal.proposal_type.value} adapter — exit code: {exec_result.exit_code}")

        # Step 6: Log execution result
        self.ledger.append(
            event_type="EXECUTION_COMPLETED" if exec_result.success else "EXECUTION_FAILED",
            proposal_id=proposal.id,
            certificate_id=cert.id,
            details=exec_result.to_dict(),
        )

        # Step 7: Revoke certificate (single use)
        cert.allowed = False
        self.ledger.append(
            event_type="CERTIFICATE_REVOKED",
            proposal_id=proposal.id,
            certificate_id=cert.id,
            details={"reason": "Single-use certificate consumed"},
        )
        result["steps"].append("6. Certificate revoked (single-use)")

        # Final status
        result["status"] = ExecutionStatus.EXECUTED.value if exec_result.success else ExecutionStatus.FAILED.value
        result["execution"] = exec_result.to_dict()

        return result

    def verify_certificate(self, cert_id: str) -> bool:
        """Verify a certificate's validity."""
        cert = self._active_certificates.get(cert_id)
        if not cert:
            return False
        return self.policy_engine.verify_certificate(cert)

    def get_audit_trail(self, proposal_id: str) -> str:
        """Get the full audit trail for a proposal."""
        return self.ledger.export_json(proposal_id)

    def verify_ledger_integrity(self) -> tuple[bool, str | None]:
        """Verify the integrity of the entire ledger."""
        return self.ledger.verify_integrity()

    @property
    def stats(self) -> dict[str, Any]:
        """Get broker statistics."""
        valid, broken = self.ledger.verify_integrity()
        return {
            "total_entries": self.ledger.size,
            "active_certificates": len(self._active_certificates),
            "ledger_integrity": valid,
            "first_broken_entry": broken,
        }

    def _execute_via_adapter(self, proposal: Proposal, certificate_id: str) -> ExecutionResult:
        """Route execution to the appropriate adapter based on proposal type."""
        match proposal.proposal_type:
            case ProposalType.FILE_WRITE | ProposalType.FILE_DELETE | ProposalType.FILE_CHMOD | ProposalType.FILE_READ:
                return self.file_adapter.execute(proposal, certificate_id)
            case ProposalType.DOCKER:
                return self.docker_adapter.execute(proposal, certificate_id)
            case ProposalType.SSH:
                return self.ssh_adapter.execute(proposal, certificate_id)
            case ProposalType.COMMAND | _:
                return self.executor.execute(proposal, certificate_id)
