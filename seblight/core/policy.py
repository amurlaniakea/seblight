# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
SEB-Light: Policy Engine (SAB — Sovereign Assurance Boundary)

Evaluates proposals against security policies and issues certificates.
This is the "admission gate" that decides if a proposal is safe to execute.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shlex
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
        """Check if this rule matches a proposal.

        Matching is resilient to whitespace/quoting evasion: the payload JSON
        AND every string value are normalized (whitespace collapse + shlex
        tokenization) before the substring check, so 'rm  -rf /' (double space)
        or 'rm -rf "/"' still trigger the 'rm -rf /' pattern.
        """
        # Check action type
        if self.action_types and proposal.proposal_type.value not in self.action_types:
            return False

        variants: set[str] = set()
        payload_str = json.dumps(proposal.payload).lower()
        variants.update(_normalized_forms(payload_str))
        for s in _iter_payload_strings(proposal.payload):
            variants.update(_normalized_forms(s))

        # Check patterns against payload
        for pattern in self.patterns:
            p = pattern.lower()
            for variant in variants:
                if p in variant:
                    return True

        return False


# ---------------------------------------------------------------------------
# Evasion-resistant matching helpers
# ---------------------------------------------------------------------------

_WS_COLLAPSE_RE = re.compile(r"\s+")


def _iter_payload_strings(obj: Any) -> list[str]:
    """Recursively collect every string value in a payload (dict/list/str)."""
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_iter_payload_strings(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_iter_payload_strings(v))
    return out


def _normalized_forms(text: str) -> list[str]:
    """Produce normalized variants of a string for pattern matching.

    - raw lowercase
    - whitespace collapsed ('rm  -rf /' -> 'rm -rf /')
    - shlex-tokenized and rejoined (quotes stripped, single spaces)
    """
    raw = text.lower()
    collapsed = _WS_COLLAPSE_RE.sub(" ", raw).strip()
    forms = [raw, collapsed]
    try:
        joined = " ".join(shlex.split(collapsed))
        if joined and joined != collapsed:
            forms.append(joined)
    except ValueError:
        pass
    seen: set[str] = set()
    unique: list[str] = []
    for f in forms:
        if f and f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# Encoded / obfuscated command detection (fail-closed)
# ---------------------------------------------------------------------------

_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_HEX_TOKEN_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_PIPE_TO_SHELL_RE = re.compile(
    r"(?:base64|xxd|hexdump|rot13|openssl\s+enc|printf\s+\S*\\x)"
    r".{0,80}(?:\||;).{0,20}(?:sh|bash|zsh|eval|source)",
    re.IGNORECASE,
)
_DECODED_DANGEROUS_MARKERS = (
    "rm -rf", "rm -fr", "mkfs.", "dd if=", "> /etc/", "chmod -R 777",
    "chmod 777 /", ":(){", "shutdown", "reboot", "poweroff",
    "iptables -F", "ufw disable", "kill -9 1", "fork bomb",
)


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for c in text if c.isprintable())
    return printable / len(text)


def _base64_candidate(token: str) -> bool:
    if not _BASE64_TOKEN_RE.fullmatch(token):
        return False
    if len(token) >= 16:
        return True
    # Shorter tokens only count when they carry the '=' padding signature
    # (e.g. 'cm0gLXJmIC8=' is 12 chars but unmistakably base64).
    return token.endswith("=") and len(token) >= 8


def detect_encoded_command(content: str) -> Severity | None:
    """Fail-closed detector for encoded/obfuscated command content.

    Returns:
      - BLOCKED if base64/hex content decodes to a dangerous command;
      - MODERATE if any base64/hex/encoded-pipe-to-shell is detectable but the
        decoded content cannot be statically resolved as safe;
      - None if the content is clean.

    Rule: any payload with detectable base64/hex/rot13 (or a pipe of decoded
    content into sh/bash/eval) is never SAFE by default — if we cannot resolve
    the decoded content statically, we fail closed (MODERATE or BLOCKED).
    """
    try:
        tokens = shlex.split(content)
    except ValueError:
        tokens = [content]

    for token in tokens:
        # base64
        if _base64_candidate(token):
            try:
                padded = token + "=" * (-len(token) % 4)
                decoded = base64.b64decode(padded, validate=True)
                text = decoded.decode("utf-8", errors="ignore")
            except Exception:
                text = ""
            if _printable_ratio(text) >= 0.7:
                if any(m in text.lower() for m in _DECODED_DANGEROUS_MARKERS):
                    return Severity.BLOCKED
                return Severity.MODERATE
            # Garbage decode: only a strong signal with the '=' padding.
            if token.endswith("="):
                return Severity.MODERATE
        # hex
        if len(token) >= 32 and _HEX_TOKEN_RE.fullmatch(token):
            try:
                decoded = bytes.fromhex(token).decode("utf-8", errors="ignore")
            except ValueError:
                decoded = ""
            if _printable_ratio(decoded) >= 0.7:
                if any(m in decoded.lower() for m in _DECODED_DANGEROUS_MARKERS):
                    return Severity.BLOCKED
                return Severity.MODERATE

    # Encoded content piped into a shell: cannot resolve statically -> fail closed.
    if _PIPE_TO_SHELL_RE.search(content):
        return Severity.MODERATE

    return None


class PolicyEngine:
    """
    Sovereign Assurance Boundary (SAB).
    Evaluates proposals against policies and issues certificates.
    """

    # Default dangerous patterns
    DEFAULT_DENY_PATTERNS = [
        "rm -rf /", "rm -rf /*", "-rf /", "rm -rf ~",
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

        # Fail-closed layer: encoded/obfuscated command content is never SAFE.
        # base64/hex/rot13 payloads (or decoded content piped to sh/bash/eval)
        # that cannot be statically resolved as safe get at least MODERATE.
        encoded_sev = self._detect_encoded(proposal)
        if encoded_sev is not None:
            matched_rules.append(f"encoded_{encoded_sev.value}")
            reasons.append(
                f"[{encoded_sev.value.upper()}] Encoded/obfuscated command payload "
                "(base64/hex/rot13 or pipe to shell) — cannot be statically "
                "resolved as safe; failing closed"
            )
            if encoded_sev == Severity.BLOCKED:
                max_severity = Severity.BLOCKED
            elif encoded_sev == Severity.MODERATE and max_severity not in (
                Severity.BLOCKED,
                Severity.DESTRUCTIVE,
            ):
                max_severity = Severity.MODERATE

        allowed = max_severity not in (Severity.BLOCKED, Severity.DESTRUCTIVE)

        if not reasons:
            reasons.append("No policy rules matched. Proposal is safe.")

        return PolicyDecision(
            allowed=allowed,
            severity=max_severity,
            reasons=reasons,
            matched_rules=matched_rules,
        )

    def _detect_encoded(self, proposal: Proposal) -> Severity | None:
        """Worst-case encoded-command severity across all payload strings."""
        worst: Severity | None = None
        for s in _iter_payload_strings(proposal.payload):
            sev = detect_encoded_command(s)
            if sev == Severity.BLOCKED:
                return Severity.BLOCKED
            if sev == Severity.MODERATE:
                worst = Severity.MODERATE
        return worst

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
