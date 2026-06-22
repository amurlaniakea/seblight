#!/usr/bin/env python3
"""
SEB-Light CLI wrapper for Hermes Agent integration.

Usage:
    python3 seblight_run.py evaluate "description" "command"
    python3 seblight_run.py execute "description" "command" [--timeout 30] [--dry-run]
    python3 seblight_run.py audit <proposal_id>
    python3 seblight_run.py verify
    python3 seblight_run.py stats
"""

import json
import sys
import os

# Add seblight to path
sys.path.insert(0, "/home/sil/seblight")

from seblight.core.broker import BrokerConfig, SovereignExecutionBroker
from seblight.core.models import Proposal, ProposalType


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]
    config = BrokerConfig(
        dry_run="--dry-run" in sys.argv,
        ledger_file=os.path.expanduser("~/.hermes/seblight-ledger.jsonl"),
    )
    broker = SovereignExecutionBroker(config)

    if command == "evaluate":
        if len(sys.argv) < 4:
            print("Usage: seblight_run.py evaluate <action> <command>")
            sys.exit(1)
        action = sys.argv[2]
        cmd = sys.argv[3]
        proposal = Proposal(
            action=action,
            proposal_type=ProposalType.COMMAND,
            payload={"command": cmd},
            actor="hermes",
        )
        decision = broker.policy_engine.evaluate(proposal)
        print(json.dumps({
            "allowed": decision.allowed,
            "severity": decision.severity.value,
            "reasons": decision.reasons,
            "matched_rules": decision.matched_rules,
        }, indent=2))

    elif command == "execute":
        if len(sys.argv) < 4:
            print("Usage: seblight_run.py execute <action> <command> [--timeout N] [--dry-run]")
            sys.exit(1)
        action = sys.argv[2]
        cmd = sys.argv[3]
        timeout = 30
        if "--timeout" in sys.argv:
            idx = sys.argv.index("--timeout")
            if idx + 1 < len(sys.argv):
                timeout = int(sys.argv[idx + 1])

        proposal = Proposal(
            action=action,
            proposal_type=ProposalType.COMMAND,
            payload={"command": cmd, "timeout": timeout},
            actor="hermes",
        )
        result = broker.process_proposal(proposal)
        print(json.dumps(result, indent=2, default=str))

    elif command == "audit":
        if len(sys.argv) < 3:
            print("Usage: seblight_run.py audit <proposal_id>")
            sys.exit(1)
        proposal_id = sys.argv[2]
        trail = broker.get_audit_trail(proposal_id)
        print(trail)

    elif command == "verify":
        valid, broken = broker.verify_ledger_integrity()
        if valid:
            print("✅ Ledger integrity: VALID")
        else:
            print(f"❌ Ledger integrity: BROKEN at entry {broken}")

    elif command == "stats":
        print(json.dumps(broker.stats, indent=2))

    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
