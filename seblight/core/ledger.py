"""
SEB-Light: Immutable Ledger

Records all decisions and executions in an append-only, hash-chained log.
Provides audit trail and integrity verification.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from .models import LedgerEntry


class Ledger:
    """
    Append-only, hash-chained ledger for recording all SEB decisions.
    Each entry contains the hash of the previous entry, forming a chain.
    """

    def __init__(self, log_file: str | None = None):
        self.entries: list[LedgerEntry] = []
        self.log_file = log_file

        if log_file and Path(log_file).exists():
            self._load_from_file(log_file)

    def append(
        self,
        event_type: str,
        proposal_id: str,
        details: dict[str, Any] | None = None,
        certificate_id: str = "",
    ) -> LedgerEntry:
        """Append a new entry to the ledger."""
        previous_hash = self.entries[-1].hash() if self.entries else ""

        entry = LedgerEntry(
            event_type=event_type,
            timestamp=time.time(),
            proposal_id=proposal_id,
            certificate_id=certificate_id,
            details=details or {},
            previous_hash=previous_hash,
        )

        self.entries.append(entry)

        if self.log_file:
            self._append_to_file(entry)

        return entry

    def verify_integrity(self) -> tuple[bool, str | None]:
        """
        Verify the integrity of the entire chain.
        Returns (valid, first_broken_entry_id).
        """
        for i, entry in enumerate(self.entries):
            if i == 0:
                continue

            expected_previous = self.entries[i - 1].hash()
            if entry.previous_hash != expected_previous:
                return False, entry.id

        return True, None

    def get_entries_for_proposal(self, proposal_id: str) -> list[LedgerEntry]:
        """Get all entries related to a specific proposal."""
        return [e for e in self.entries if e.proposal_id == proposal_id]

    def export_json(self, proposal_id: str | None = None) -> str:
        """Export ledger entries as JSON."""
        entries = (
            self.get_entries_for_proposal(proposal_id)
            if proposal_id
            else self.entries
        )
        return json.dumps(
            [
                {
                    "id": e.id,
                    "event_type": e.event_type,
                    "timestamp": e.timestamp,
                    "proposal_id": e.proposal_id,
                    "certificate_id": e.certificate_id,
                    "details": e.details,
                    "previous_hash": e.previous_hash,
                    "hash": e.hash(),
                }
                for e in entries
            ],
            indent=2,
        )

    def _append_to_file(self, entry: LedgerEntry):
        """Append an entry to the log file."""
        data = {
            "id": entry.id,
            "event_type": entry.event_type,
            "timestamp": entry.timestamp,
            "proposal_id": entry.proposal_id,
            "certificate_id": entry.certificate_id,
            "details": entry.details,
            "previous_hash": entry.previous_hash,
            "hash": entry.hash(),
        }
        with open(self.log_file, "a") as f:
            f.write(json.dumps(data) + "\n")

    def _load_from_file(self, path: str):
        """Load entries from a log file."""
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                entry = LedgerEntry(
                    event_type=data["event_type"],
                    timestamp=data["timestamp"],
                    proposal_id=data["proposal_id"],
                    certificate_id=data.get("certificate_id", ""),
                    details=data.get("details", {}),
                    previous_hash=data.get("previous_hash", ""),
                    id=data.get("id", ""),
                )
                self.entries.append(entry)

    @property
    def size(self) -> int:
        return len(self.entries)
