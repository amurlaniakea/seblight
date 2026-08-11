# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
SEB-Light: Command Executor

Executes approved proposals (shell commands) with safety controls.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from typing import Any

from .models import ExecutionResult, Proposal

# Characters that only have meaning through a shell. Unquoted occurrences are
# rejected before execution (the executor runs shell=False).
_SHELL_CONTROL_CHARS = set("$`\\|;&><(){}!\n")


def _has_unquoted_shell_control(command: str) -> bool:
    """True if the command has shell control characters OUTSIDE quotes.

    Characters inside single/double quotes or escaped by backslash are DATA,
    not shell syntax (e.g. python3 -c "import sys; sys.exit(42)" keeps its
    quoted ';' and stays allowed).
    """
    quote: str | None = None
    escaped = False
    for ch in command:
        if escaped:
            escaped = False
            continue
        if ch == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch in _SHELL_CONTROL_CHARS:
            return True
    return False


class CommandExecutor:
    """
    Executes shell commands from approved proposals.
    Enforces timeouts, output limits, and safety checks.

    SECURITY CONTRACT (T5): this executor NEVER runs a shell. The command is
    tokenized with shlex and executed with shell=False as a plain argv list.
    Unquoted shell control characters (| ; & > < $ ` \\ ( ) { } !) are rejected
    up front (fail closed, clear error): a full shell is a programming
    language with infinitely many ways to build a string (variable
    concatenation, ${IFS}, printf octal escapes, ...), so text analysis can
    never cover them all — removing the shell removes the class entirely.

    KNOWN REMAINING GAP (depth-in-defense, not a complete solution):
    interpreted languages invoked with -c/-e (python3 -c "print(chr(114)+...)",
    perl -e, node -e...) execute arbitrary code as a plain argv program and
    are NOT closable by static text analysis. Closing that class requires
    sandboxing (nsjail/container) or an allowlist of invocable binaries.
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

        # Fail closed: unquoted shell control characters mean the proposal
        # needs a shell to mean anything — and this executor never runs one.
        if _has_unquoted_shell_control(command):
            return ExecutionResult(
                success=False,
                certificate_id=certificate_id,
                proposal_id=proposal.id,
                error=(
                    "Shell control characters (| ; & > < $ ` \\ ( ) { } !) are "
                    "not allowed in COMMAND proposals — this executor runs "
                    "without a shell (shell=False). Submit discrete steps or a "
                    "single executable with arguments."
                ),
                exit_code=1,
            )

        # Tokenize with shlex (quote-aware, no shell interpretation) and run as
        # a plain argv list.
        try:
            argv = shlex.split(command)
        except ValueError as e:
            return ExecutionResult(
                success=False,
                certificate_id=certificate_id,
                proposal_id=proposal.id,
                error=f"Unparseable command: {e}",
                exit_code=1,
            )
        if not argv:
            return ExecutionResult(
                success=False,
                certificate_id=certificate_id,
                proposal_id=proposal.id,
                error="No command specified in proposal payload",
                exit_code=1,
            )

        # Sanitize environment
        env = self._build_env()

        started_at = time.time()

        try:
            result = subprocess.run(
                argv,
                shell=False,  # argv list; never a shell string
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
