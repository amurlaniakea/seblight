# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
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

            # Build SSH command as an argument LIST (never a shell string).
            # The host/user/key_file/command are isolated argv elements, so a
            # host like 'x; rm -rf ~' cannot inject a second local command.
            ssh_cmd = self._build_command(
                host=str(host),
                command=str(command),
                user=str(user),
                port=int(port),
                key_file=str(key_file),
            )

            result = subprocess.run(
                ssh_cmd,
                shell=False,  # ssh_cmd is an argument list; never a shell string
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

    def _build_command(
        self,
        host: str,
        command: str,
        user: str,
        port: int,
        key_file: str,
    ) -> list[str]:
        """Build the ssh argv list (shell=False, no local injection possible)."""
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-p", str(port),
        ]
        if key_file:
            cmd += ["-i", key_file]
        cmd += [f"{user}@{host}", command]
        return cmd

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
