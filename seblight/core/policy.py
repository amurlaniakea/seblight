"""
SEB-Light: Policy Engine (SAB — Sovereign Assurance Boundary)

Evaluates proposals against security policies and issues certificates.
This is the "admission gate" that decides if a proposal is safe to execute.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import (
    Certificate,
    PolicyDecision,
    Proposal,
    Severity,
)


@dataclass
class PolicyRule:
    """A single policy rule."""
    name: str
    description: str
    severity: Severity
    # Patterns that trigger this rule (matched against proposal payload)
    patterns: list[str] = field(default_factory=list)
    # Action types this rule applies to
    action_types: list[str] = field(default_factory=list)
    # Whether this rule blocks or allows
    effect: str = "deny"  # "deny" or "allow"
    # Priority (higher = evaluated first)
    priority: int = 0

    def matches(self, proposal: Proposal) -> bool:
        """Check if this rule matches a proposal."""
        # Check action type
        if self.action_types and proposal.proposal_type.value not in self.action_types:
            return False

        # Check patterns against payload
        payload_str = json.dumps(proposal.payload).lower()
        for pattern in self.patterns:
            if pattern.lower() in payload_str:
                return True

        return False


class PolicyEngine:
    """
    Sovereign Assurance Boundary (SAB).
    Evaluates proposals against policies and issues certificates.
    """

    # Default dangerous patterns
    DEFAULT_DENY_PATTERNS = [
        "rm -rf /", "rm -rf /*", "rm -rf ~",
        "mkfs.", "dd if=/dev/zero of=/dev/",
        "chmod -R 777 /", "chmod -R 777 /*",
        "> /etc/passwd", "> /etc/shadow",
        "iptables -F", "ufw disable",
        "systemctl stop", "systemctl disable",
        "docker rm -f", "docker system prune -a",
        "drop table", "drop database", "delete from",
        "shutdown", "reboot", "poweroff",
        "kill -9 1", "killall -9",
        ":(){:|:&};:",  # fork bomb
    ]

    DEFAULT_MODERATE_PATTERNS = [
        "rm -rf", "rm -r", "rm ",
        "mv ", "cp -r ",
        "chmod ", "chown ",
        "apt remove", "apt purge", "pip uninstall",
        "docker stop", "docker kill", "docker rm",
        "docker build", "docker pull",
        "systemctl restart", "service restart",
        "curl ", "wget ", "nc ", "ncat ",
        "ssh ", "scp ", "rsync ",
    ]

    def __init__(
        self,
        secret_key: str | None = None,
        policy_file: str | None = None,
    ):
        self.secret_key = secret_key or os.urandom(32).hex()
        self.rules: list[PolicyRule] = []
        self._load_default_rules()

        if policy_file and Path(policy_file).exists():
            self._load_policy_file(policy_file)

    def _load_default_rules(self):
        """Load default security rules."""
        # Block rules (highest priority)
        for pattern in self.DEFAULT_DENY_PATTERNS:
            self.rules.append(PolicyRule(
                name=f"deny_{pattern.replace(' ', '_').replace('/', '_')}",
                description=f"Dangerous pattern blocked: {pattern}",
                severity=Severity.BLOCKED,
                patterns=[pattern],
                effect="deny",
                priority=100,
            ))

        # Moderate rules
        for pattern in self.DEFAULT_MODERATE_PATTERNS:
            self.rules.append(PolicyRule(
                name=f"moderate_{pattern.replace(' ', '_').replace('/', '_')}",
                description=f"Moderate-risk pattern: {pattern}",
                severity=Severity.MODERATE,
                patterns=[pattern],
                effect="deny",
                priority=50,
            ))

        # Sort by priority (highest first)
        self.rules.sort(key=lambda r: r.priority, reverse=True)

    def _load_policy_file(self, path: str):
        """Load additional rules from a YAML/JSON policy file."""
        import json
        with open(path) as f:
            data = json.load(f)
        for rule_data in data.get("rules", []):
            self.rules.append(PolicyRule(
                name=rule_data["name"],
                description=rule_data.get("description", ""),
                severity=Severity(rule_data.get("severity", "moderate")),
                patterns=rule_data.get("patterns", []),
                action_types=rule_data.get("action_types", []),
                effect=rule_data.get("effect", "deny"),
                priority=rule_data.get("priority", 0),
            ))
        self.rules.sort(key=lambda r: r.priority, reverse=True)

    def evaluate(self, proposal: Proposal) -> PolicyDecision:
        """
        Evaluate a proposal against all rules.
        Returns a PolicyDecision.
        """
        matched_rules = []
        max_severity = Severity.SAFE
        reasons = []

        for rule in self.rules:
            if rule.matches(proposal):
                matched_rules.append(rule.name)
                reasons.append(f"[{rule.severity.value.upper()}] {rule.description}")

                if rule.severity == Severity.BLOCKED:
                    max_severity = Severity.BLOCKED
                elif rule.severity == Severity.MODERATE and max_severity != Severity.BLOCKED:
                    max_severity = Severity.MODERATE
                elif rule.severity == Severity.DESTRUCTIVE and max_severity not in (Severity.BLOCKED, Severity.MODERATE):
                    max_severity = Severity.DESTRUCTIVE

        allowed = max_severity not in (Severity.BLOCKED, Severity.DESTRUCTIVE)

        if not reasons:
            reasons.append("No policy rules matched. Proposal is safe.")

        return PolicyDecision(
            allowed=allowed,
            severity=max_severity,
            reasons=reasons,
            matched_rules=matched_rules,
        )

    def issue_certificate(self, proposal: Proposal, decision: PolicyDecision) -> Certificate:
        """
        Issue a certificate for an approved proposal.
        The certificate is cryptographically signed.
        """
        fingerprint = proposal.fingerprint()

        cert = Certificate(
            proposal_id=proposal.id,
            proposal_fingerprint=fingerprint,
            severity=decision.severity,
            allowed=decision.allowed,
            scope=[proposal.proposal_type.value],
            constraints={
                "matched_rules": decision.matched_rules,
                "max_duration_seconds": 300 if decision.allowed else 0,
            },
        )

        # Sign the certificate
        cert.signature = self._sign_certificate(cert)

        return cert

    def _sign_certificate(self, cert: Certificate) -> str:
        """Create HMAC signature for a certificate."""
        data = f"{cert.proposal_id}:{cert.proposal_fingerprint}:{cert.issued_at}:{cert.expires_at}"
        return hmac.new(
            self.secret_key.encode(),
            data.encode(),
            hashlib.sha256,
        ).hexdigest()

    def verify_certificate(self, cert: Certificate) -> bool:
        """Verify a certificate's signature and validity."""
        if cert.is_expired:
            return False
        if not cert.allowed:
            return False

        expected_sig = self._sign_certificate(cert)
        return hmac.compare_digest(cert.signature, expected_sig)
