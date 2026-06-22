"""
SEB-Light: Sovereign Execution Broker (Python implementation)
Based on: "Sovereign Execution Brokers: Enforcing Certificate-Bound Authority
          in Agentic Control Planes" (arXiv:2606.20520, Jun 2026)

Core data structures: Proposal, Certificate, Policy, ExecutionResult
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProposalType(str, Enum):
    """Types of proposals an agent can submit."""
    COMMAND = "command"           # Shell command
    FILE_WRITE = "file_write"     # Write to file
    FILE_DELETE = "file_delete"   # Delete file
    NETWORK = "network"           # Network operation
    PROCESS = "process"           # Process management
    CUSTOM = "custom"             # Custom operation


class Severity(str, Enum):
    """Severity levels for policy decisions."""
    SAFE = "safe"                 # No approval needed
    MODERATE = "moderate"         # Warn user, proceed after timeout
    DESTRUCTIVE = "destructive"   # Explicit approval required
    BLOCKED = "blocked"           # Always blocked


class ExecutionStatus(str, Enum):
    """Status of execution."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    REVOKED = "revoked"


@dataclass
class Proposal:
    """
    A proposal is what an agent wants to execute.
    Equivalent to 'Intent' in OpenKedge.
    """
    action: str                          # Human-readable action description
    proposal_type: ProposalType          # Type of proposal
    payload: dict[str, Any]              # Action-specific data
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    actor: str = "unknown"               # Who/what submitted the proposal

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "proposal_type": self.proposal_type.value,
            "payload": self.payload,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
            "actor": self.actor,
        }

    def fingerprint(self) -> str:
        """Cryptographic fingerprint of this proposal."""
        data = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class Certificate:
    """
    A certificate is issued by the SAB (Sovereign Assurance Boundary)
    after validating a proposal. It binds authority to a specific action.
    Equivalent to certificate Ω in the paper.
    """
    proposal_id: str                     # Which proposal this certifies
    proposal_fingerprint: str            # Fingerprint of the original proposal
    severity: Severity                   # Severity classification
    allowed: bool                        # Whether the proposal is allowed
    scope: list[str]                     # What operations are permitted
    constraints: dict[str, Any] = field(default_factory=dict)
    issued_at: float = field(default_factory=time.time)
    expires_at: float = 0.0              # Expiration timestamp
    issuer: str = "seblight-sab"         # Who issued the certificate
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    signature: str = ""                  # Cryptographic signature

    def __post_init__(self):
        if self.expires_at == 0.0:
            # Default: 5 minute validity window
            self.expires_at = self.issued_at + 300

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return self.allowed and not self.is_expired and self.signature != ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "proposal_id": self.proposal_id,
            "proposal_fingerprint": self.proposal_fingerprint,
            "severity": self.severity.value,
            "allowed": self.allowed,
            "scope": self.scope,
            "constraints": self.constraints,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "issuer": self.issuer,
            "signature": self.signature,
        }


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""
    allowed: bool
    severity: Severity
    reasons: list[str]
    matched_rules: list[str] = field(default_factory=list)
    constraints: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Result of executing a proposal."""
    success: bool
    certificate_id: str
    proposal_id: str
    output: str = ""
    error: str = ""
    exit_code: int = 0
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def duration_ms(self) -> float:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at) * 1000
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "certificate_id": self.certificate_id,
            "proposal_id": self.proposal_id,
            "output": self.output,
            "error": self.error,
            "exit_code": self.exit_code,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
        }


@dataclass
class LedgerEntry:
    """
    An immutable entry in the decision ledger.
    Each entry represents a step in the SEB pipeline.
    """
    event_type: str                      # Type of event
    timestamp: float                     # When it happened
    proposal_id: str                     # Related proposal
    certificate_id: str = ""             # Related certificate (if any)
    details: dict[str, Any] = field(default_factory=dict)
    previous_hash: str = ""              # Hash chain for integrity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def hash(self) -> str:
        """Compute hash of this entry for chain integrity."""
        data = json.dumps({
            "id": self.id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "proposal_id": self.proposal_id,
            "certificate_id": self.certificate_id,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()
