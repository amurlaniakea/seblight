# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
SEB-Light: Docker Operations Adapter

Handles Docker container and image operations through SEB.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import time
from typing import Any

from ..core.models import ExecutionResult, Proposal


class DockerAdapter:
    """
    Executes Docker operations from approved proposals.
    Supports: run, stop, rm, build, pull, ps, logs, exec.
    """

    # Dangerous Docker operations that are always blocked
    BLOCKED_OPERATIONS = [
        "system prune", "volume prune", "network prune",
        "rmi -f", "rm -f",
    ]

    # Host paths that must never be bind-mounted into a container
    SENSITIVE_HOST_PATHS = ("/", "/etc", "/root", "/home")

    def __init__(self, default_timeout: int = 60):
        self.default_timeout = default_timeout

    def execute(self, proposal: Proposal, certificate_id: str = "") -> ExecutionResult:
        """Execute a Docker operation from a proposal."""
        started_at = time.time()

        try:
            operation = proposal.payload.get("operation", "")
            if not operation:
                return self._error(certificate_id, proposal.id, started_at, "No operation specified")

            if self._is_blocked(operation):
                return self._error(certificate_id, proposal.id, started_at, f"Docker operation blocked: {operation}")

            # Reject volume mounts that expose sensitive host paths (fail closed).
            # A mount like '-v /:/host' would give the container the host root
            # filesystem and is NOT caught by the policy engine's payload match.
            for vol in proposal.payload.get("volumes", []):
                if self._is_sensitive_volume(str(vol)):
                    return self._error(
                        certificate_id,
                        proposal.id,
                        started_at,
                        f"Volume mount rejected: '{vol}' points to sensitive host path",
                    )

            # Build the docker command
            cmd = self._build_command(proposal.payload)
            if not cmd:
                return self._error(certificate_id, proposal.id, started_at, f"Unknown operation: {operation}")

            timeout = proposal.payload.get("timeout", self.default_timeout)

            result = subprocess.run(
                cmd,
                shell=False,  # cmd is an argument list; never a shell string
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
            return self._error(certificate_id, proposal.id, started_at, f"Docker operation timed out after {self.default_timeout}s")
        except Exception as e:
            return self._error(certificate_id, proposal.id, started_at, str(e))

    def _build_command(self, payload: dict[str, Any]) -> list[str] | None:
        """Build a Docker command as an argument LIST (never a shell string).

        Returning a list and running with shell=False removes shell injection
        entirely: every payload field (image, name, ports, volumes, env) is
        passed to docker as an isolated argv element. The 'command' field is
        tokenized with shlex (safe: no shell interpretation).
        """
        operation = payload.get("operation", "")

        if operation == "run":
            image = payload.get("image", "")
            name = payload.get("name", "")
            ports = payload.get("ports", [])
            volumes = payload.get("volumes", [])
            env = payload.get("env", {})
            detach = payload.get("detach", True)
            rm = payload.get("rm", False)
            command = payload.get("command", "")

            cmd = ["docker", "run"]
            if detach:
                cmd.append("-d")
            if rm:
                cmd.append("--rm")
            if name:
                cmd += ["--name", str(name)]
            for p in ports:
                cmd += ["-p", str(p)]
            for v in volumes:
                cmd += ["-v", str(v)]
            for k, v in env.items():
                cmd += ["-e", f"{k}={v}"]
            cmd.append(str(image))
            if command:
                cmd += self._split_command(str(command))
            return cmd

        elif operation == "stop":
            container = payload.get("container", "")
            timeout = payload.get("timeout", 10)
            return ["docker", "stop", "-t", str(timeout), str(container)]

        elif operation == "rm":
            container = payload.get("container", "")
            force = payload.get("force", False)
            cmd = ["docker", "rm", str(container)]
            if force:
                cmd.append("-f")
            return cmd

        elif operation == "build":
            path = payload.get("path", ".")
            tag = payload.get("tag", "")
            dockerfile = payload.get("dockerfile", "")
            cmd = ["docker", "build"]
            if tag:
                cmd += ["-t", str(tag)]
            if dockerfile:
                cmd += ["-f", str(dockerfile)]
            cmd.append(str(path))
            return cmd

        elif operation == "pull":
            image = payload.get("image", "")
            return ["docker", "pull", str(image)]

        elif operation == "ps":
            all_containers = payload.get("all", False)
            return ["docker", "ps", "-a"] if all_containers else ["docker", "ps"]

        elif operation == "logs":
            container = payload.get("container", "")
            tail = payload.get("tail", 100)
            follow = payload.get("follow", False)
            cmd = ["docker", "logs", "--tail", str(tail), str(container)]
            if follow:
                cmd.append("-f")
            return cmd

        elif operation == "exec":
            container = payload.get("container", "")
            command = payload.get("command", "")
            interactive = payload.get("interactive", False)
            cmd = ["docker", "exec"]
            if interactive:
                cmd.append("-it")
            cmd.append(str(container))
            if command:
                cmd += self._split_command(str(command))
            return cmd

        elif operation == "images":
            return ["docker", "images"]

        elif operation == "inspect":
            target = payload.get("target", "")
            return ["docker", "inspect", str(target)]

        return None

    def _split_command(self, command: str) -> list[str]:
        """Tokenize a command field with shlex (no shell interpretation)."""
        try:
            return shlex.split(command)
        except ValueError:
            raise ValueError(f"Unparseable command field: {command!r}") from None

    def _is_sensitive_volume(self, volume: str) -> bool:
        """True if a '-v' spec bind-mounts a sensitive host path.

        Checks the SOURCE part of 'source:target[:opts]': the host root and
        critical directories (/, /etc, /root, /home) must never be mounted.
        Anonymous volumes (empty source) are allowed.
        """
        source = volume.split(":", 1)[0].strip() if ":" in volume else volume.strip()
        if not source:
            return False  # anonymous volume
        if source in self.SENSITIVE_HOST_PATHS:
            return True
        return source.startswith(("/etc/", "/root/", "/home/"))

    def _is_blocked(self, operation: str) -> bool:
        """Check if a Docker operation is blocked."""
        op_lower = operation.lower()
        for blocked in self.BLOCKED_OPERATIONS:
            if blocked in op_lower:
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
