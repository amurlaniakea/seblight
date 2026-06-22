"""
SEB-Light: File Operations Adapter

Handles file write, delete, chmod, and read operations through SEB.
"""

from __future__ import annotations

import os
import shutil
import stat
import time
from pathlib import Path
from typing import Any

from ..core.models import ExecutionResult, Proposal, ProposalType


class FileAdapter:
    """
    Executes file operations from approved proposals.
    Supports: write, delete, chmod, read.
    """

    # Paths that are always blocked
    BLOCKED_PATHS = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/hosts", "/etc/resolv.conf",
        "/boot", "/proc", "/sys",
    ]

    def __init__(self, max_file_size: int = 10_000_000):  # 10MB
        self.max_file_size = max_file_size

    def execute(self, proposal: Proposal, certificate_id: str = "") -> ExecutionResult:
        """Execute a file operation from a proposal."""
        started_at = time.time()

        try:
            if proposal.proposal_type == ProposalType.FILE_WRITE:
                return self._write(proposal, certificate_id, started_at)
            elif proposal.proposal_type == ProposalType.FILE_DELETE:
                return self._delete(proposal, certificate_id, started_at)
            elif proposal.proposal_type == ProposalType.FILE_CHMOD:
                return self._chmod(proposal, certificate_id, started_at)
            elif proposal.proposal_type == ProposalType.FILE_READ:
                return self._read(proposal, certificate_id, started_at)
            else:
                return self._error(certificate_id, proposal.id, started_at, f"Unsupported file operation: {proposal.proposal_type}")
        except Exception as e:
            return self._error(certificate_id, proposal.id, started_at, str(e))

    def _write(self, proposal: Proposal, cert_id: str, started_at: float) -> ExecutionResult:
        path = proposal.payload.get("path", "")
        content = proposal.payload.get("content", "")
        mode = proposal.payload.get("mode", "w")  # "w" or "append"
        create_dirs = proposal.payload.get("create_dirs", True)

        if not path:
            return self._error(cert_id, proposal.id, started_at, "No path specified")

        if self._is_blocked(path):
            return self._error(cert_id, proposal.id, started_at, f"Path is blocked: {path}")

        p = Path(path)

        if create_dirs and not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)

        if mode == "append":
            with open(p, "a") as f:
                f.write(content)
        else:
            with open(p, "w") as f:
                f.write(content)

        size = p.stat().st_size
        completed_at = time.time()

        return ExecutionResult(
            success=True,
            certificate_id=cert_id,
            proposal_id=proposal.id,
            output=f"Written {size} bytes to {path}",
            exit_code=0,
            started_at=started_at,
            completed_at=completed_at,
        )

    def _delete(self, proposal: Proposal, cert_id: str, started_at: float) -> ExecutionResult:
        path = proposal.payload.get("path", "")
        recursive = proposal.payload.get("recursive", False)

        if not path:
            return self._error(cert_id, proposal.id, started_at, "No path specified")

        if self._is_blocked(path):
            return self._error(cert_id, proposal.id, started_at, f"Path is blocked: {path}")

        p = Path(path)
        if not p.exists():
            return self._error(cert_id, proposal.id, started_at, f"Path does not exist: {path}")

        if p.is_dir():
            if recursive:
                shutil.rmtree(p)
            else:
                p.rmdir()
        else:
            p.unlink()

        completed_at = time.time()
        return ExecutionResult(
            success=True,
            certificate_id=cert_id,
            proposal_id=proposal.id,
            output=f"Deleted {path}",
            exit_code=0,
            started_at=started_at,
            completed_at=completed_at,
        )

    def _chmod(self, proposal: Proposal, cert_id: str, started_at: float) -> ExecutionResult:
        path = proposal.payload.get("path", "")
        mode_str = proposal.payload.get("mode", "")

        if not path or not mode_str:
            return self._error(cert_id, proposal.id, started_at, "Path and mode required")

        if self._is_blocked(path):
            return self._error(cert_id, proposal.id, started_at, f"Path is blocked: {path}")

        p = Path(path)
        if not p.exists():
            return self._error(cert_id, proposal.id, started_at, f"Path does not exist: {path}")

        # Parse mode (e.g., "755", "644")
        try:
            mode = int(mode_str, 8)
        except ValueError:
            return self._error(cert_id, proposal.id, started_at, f"Invalid mode: {mode_str}")

        p.chmod(mode)
        completed_at = time.time()

        return ExecutionResult(
            success=True,
            certificate_id=cert_id,
            proposal_id=proposal.id,
            output=f"Changed mode of {path} to {mode_str} ({oct(mode)})",
            exit_code=0,
            started_at=started_at,
            completed_at=completed_at,
        )

    def _read(self, proposal: Proposal, cert_id: str, started_at: float) -> ExecutionResult:
        path = proposal.payload.get("path", "")
        max_bytes = proposal.payload.get("max_bytes", self.max_file_size)

        if not path:
            return self._error(cert_id, proposal.id, started_at, "No path specified")

        p = Path(path)
        if not p.exists():
            return self._error(cert_id, proposal.id, started_at, f"Path does not exist: {path}")

        if not p.is_file():
            return self._error(cert_id, proposal.id, started_at, f"Not a file: {path}")

        size = p.stat().st_size
        if size > self.max_file_size:
            return self._error(cert_id, proposal.id, started_at, f"File too large: {size} bytes (max: {self.max_file_size})")

        with open(p, "r") as f:
            content = f.read(max_bytes)

        completed_at = time.time()
        return ExecutionResult(
            success=True,
            certificate_id=cert_id,
            proposal_id=proposal.id,
            output=content,
            exit_code=0,
            started_at=started_at,
            completed_at=completed_at,
        )

    def _is_blocked(self, path: str) -> bool:
        """Check if a path is blocked."""
        resolved = str(Path(path).resolve())
        for blocked in self.BLOCKED_PATHS:
            if resolved.startswith(blocked) or resolved == blocked:
                return True
        return False

    def _error(self, cert_id: str, proposal_id: str, started_at: float, msg: str) -> ExecutionResult:
        return ExecutionResult(
            success=False,
            certificate_id=cert_id,
            proposal_id=proposal_id,
            error=msg,
            exit_code=1,
            started_at=started_at,
            completed_at=time.time(),
        )
