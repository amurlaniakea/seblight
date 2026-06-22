"""
SEB-Light: Command Executor

Executes approved proposals (shell commands) with safety controls.
"""

from __future__ import annotations

import subprocess
import time
from typing import Any

from .models import ExecutionResult, Proposal


class CommandExecutor:
    """
    Executes shell commands from approved proposals.
    Enforces timeouts, output limits, and safety checks.
    """

    def __init__(
        self,
        default_timeout: int = 30,
        max_output_bytes: int = 1_000_000,  # 1MB
        allowed_env_vars: list[str] | None = None,
    ):
        self.default_timeout = default_timeout
        self.max_output_bytes = max_output_bytes
        self.allowed_env_vars = allowed_env_vars or [
            "PATH", "HOME", "USER", "LANG", "LC_ALL",
            "TERM", "SHELL", "PWD", "OLDPWD",
        ]

    def execute(
        self,
        proposal: Proposal,
        certificate_id: str = "",
        dry_run: bool = False,
    ) -> ExecutionResult:
        """
        Execute a command from an approved proposal.
        """
        command = proposal.payload.get("command", "")
        timeout = proposal.payload.get("timeout", self.default_timeout)
        working_dir = proposal.payload.get("cwd", None)

        if not command:
            return ExecutionResult(
                success=False,
                certificate_id=certificate_id,
                proposal_id=proposal.id,
                error="No command specified in proposal payload",
            )

        if dry_run:
            return ExecutionResult(
                success=True,
                certificate_id=certificate_id,
                proposal_id=proposal.id,
                output=f"[DRY RUN] Would execute: {command}",
                exit_code=0,
            )

        # Sanitize environment
        env = self._build_env()

        started_at = time.time()

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=working_dir,
            )

            completed_at = time.time()

            # Truncate output if too large
            stdout = result.stdout[:self.max_output_bytes]
            stderr = result.stderr[:self.max_output_bytes]

            output = stdout
            if stderr:
                output += f"\n[STDERR]\n{stderr}"

            return ExecutionResult(
                success=result.returncode == 0,
                certificate_id=certificate_id,
                proposal_id=proposal.id,
                output=output,
                error=stderr if result.returncode != 0 else "",
                exit_code=result.returncode,
                started_at=started_at,
                completed_at=completed_at,
            )

        except subprocess.TimeoutExpired:
            completed_at = time.time()
            return ExecutionResult(
                success=False,
                certificate_id=certificate_id,
                proposal_id=proposal.id,
                error=f"Command timed out after {timeout}s",
                exit_code=-1,
                started_at=started_at,
                completed_at=completed_at,
            )

        except Exception as e:
            completed_at = time.time()
            return ExecutionResult(
                success=False,
                certificate_id=certificate_id,
                proposal_id=proposal.id,
                error=str(e),
                exit_code=-1,
                started_at=started_at,
                completed_at=completed_at,
            )

    def _build_env(self) -> dict[str, str]:
        """Build a sanitized environment for command execution."""
        env = {}
        for var in self.allowed_env_vars:
            value = __import__("os").environ.get(var)
            if value is not None:
                env[var] = value
        return env
