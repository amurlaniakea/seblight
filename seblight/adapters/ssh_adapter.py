"""
SEB-Light: SSH Remote Execution Adapter

Handles remote command execution via SSH through SEB.
"""

from __future__ import annotations

import subprocess
import time
from typing import Any

from ..core.models import ExecutionResult, Proposal


class SSHAdapter:
    """
    Executes remote commands via SSH from approved proposals.
    """

    def __init__(self, default_timeout: int = 60, default_user: str = "root"):
        self.default_timeout = default_timeout
        self.default_user = default_user

    def execute(self, proposal: Proposal, certificate_id: str = "") -> ExecutionResult:
        """Execute an SSH operation from a proposal."""
        started_at = time.time()

        try:
            host = proposal.payload.get("host", "")
            command = proposal.payload.get("command", "")
            user = proposal.payload.get("user", self.default_user)
            port = proposal.payload.get("port", 22)
            key_file = proposal.payload.get("key_file", "")
            timeout = proposal.payload.get("timeout", self.default_timeout)

            if not host or not command:
                return self._error(certificate_id, proposal.id, started_at, "Host and command required")

            # Build SSH command
            ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p {port}"
            if key_file:
                ssh_cmd += f" -i {key_file}"
            ssh_cmd += f" {user}@{host} '{command}'"

            result = subprocess.run(
                ssh_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            completed_at = time.time()

            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"

            return ExecutionResult(
                success=result.returncode == 0,
                certificate_id=certificate_id,
                proposal_id=proposal.id,
                output=output.strip(),
                error=result.stderr if result.returncode != 0 else "",
                exit_code=result.returncode,
                started_at=started_at,
                completed_at=completed_at,
            )

        except subprocess.TimeoutExpired:
            return self._error(certificate_id, proposal.id, started_at, f"SSH operation timed out after {self.default_timeout}s")
        except Exception as e:
            return self._error(certificate_id, proposal.id, started_at, str(e))

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
