"""
SEB-Light: Docker Operations Adapter

Handles Docker container and image operations through SEB.
"""

from __future__ import annotations

import json
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

            # Build the docker command
            cmd = self._build_command(proposal.payload)
            if not cmd:
                return self._error(certificate_id, proposal.id, started_at, f"Unknown operation: {operation}")

            timeout = proposal.payload.get("timeout", self.default_timeout)

            result = subprocess.run(
                cmd,
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
            return self._error(certificate_id, proposal.id, started_at, f"Docker operation timed out after {self.default_timeout}s")
        except Exception as e:
            return self._error(certificate_id, proposal.id, started_at, str(e))

    def _build_command(self, payload: dict[str, Any]) -> str:
        """Build a Docker command from payload."""
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

            cmd = "docker run"
            if detach:
                cmd += " -d"
            if rm:
                cmd += " --rm"
            if name:
                cmd += f" --name {name}"
            for p in ports:
                cmd += f" -p {p}"
            for v in volumes:
                cmd += f" -v {v}"
            for k, v in env.items():
                cmd += f" -e {k}={v}"
            cmd += f" {image}"
            if command:
                cmd += f" {command}"
            return cmd

        elif operation == "stop":
            container = payload.get("container", "")
            timeout = payload.get("timeout", 10)
            return f"docker stop -t {timeout} {container}"

        elif operation == "rm":
            container = payload.get("container", "")
            force = payload.get("force", False)
            cmd = f"docker rm {container}"
            if force:
                cmd += " -f"
            return cmd

        elif operation == "build":
            path = payload.get("path", ".")
            tag = payload.get("tag", "")
            dockerfile = payload.get("dockerfile", "")
            cmd = f"docker build"
            if tag:
                cmd += f" -t {tag}"
            if dockerfile:
                cmd += f" -f {dockerfile}"
            cmd += f" {path}"
            return cmd

        elif operation == "pull":
            image = payload.get("image", "")
            return f"docker pull {image}"

        elif operation == "ps":
            all_containers = payload.get("all", False)
            return "docker ps -a" if all_containers else "docker ps"

        elif operation == "logs":
            container = payload.get("container", "")
            tail = payload.get("tail", 100)
            follow = payload.get("follow", False)
            cmd = f"docker logs --tail {tail} {container}"
            if follow:
                cmd += " -f"
            return cmd

        elif operation == "exec":
            container = payload.get("container", "")
            command = payload.get("command", "")
            interactive = payload.get("interactive", False)
            cmd = f"docker exec"
            if interactive:
                cmd += " -it"
            cmd += f" {container} {command}"
            return cmd

        elif operation == "images":
            return "docker images"

        elif operation == "inspect":
            target = payload.get("target", "")
            return f"docker inspect {target}"

        return ""

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
