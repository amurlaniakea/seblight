# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SEB-Light adapters."""

from .docker_adapter import DockerAdapter
from .file_adapter import FileAdapter
from .ssh_adapter import SSHAdapter

__all__ = ["FileAdapter", "DockerAdapter", "SSHAdapter"]
