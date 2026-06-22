"""
SEB-Light: Command Line Interface

Usage:
    seblight evaluate --command "ls -la" --actor "hermes"
    seblight execute --command "echo hello" --actor "hermes" [--dry-run]
    seblight audit --proposal-id <id>
    seblight stats
    seblight verify
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..core.broker import BrokerConfig, SovereignExecutionBroker
from ..core.models import Proposal, ProposalType


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seblight",
        description="SEB-Light: Sovereign Execution Broker (Python)",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # evaluate
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate a proposal without executing")
    eval_parser.add_argument("--action", required=True, help="Action description")
    eval_parser.add_argument("--type", default="command", help="Proposal type")
    eval_parser.add_argument("--payload", default="{}", help="JSON payload")
    eval_parser.add_argument("--actor", default="cli", help="Actor name")

    # execute
    exec_parser = subparsers.add_parser("execute", help="Execute a proposal through SEB")
    exec_parser.add_argument("--action", required=True, help="Action description")
    exec_parser.add_argument("--type", default="command", help="Proposal type")
    exec_parser.add_argument("--payload", default="{}", help="JSON payload")
    exec_parser.add_argument("--actor", default="cli", help="Actor name")
    exec_parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    exec_parser.add_argument("--timeout", type=int, default=30, help="Command timeout")

    # audit
    audit_parser = subparsers.add_parser("audit", help="Show audit trail for a proposal")
    audit_parser.add_argument("--proposal-id", required=True, help="Proposal ID")

    # stats
    subparsers.add_parser("stats", help="Show broker statistics")

    # verify
    subparsers.add_parser("verify", help="Verify ledger integrity")

    # Common args
    parser.add_argument("--ledger-file", default=None, help="Ledger log file path")
    parser.add_argument("--policy-file", default=None, help="Policy file path")
    parser.add_argument("--secret-key", default=None, help="Secret key for signing")

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    config = BrokerConfig(
        policy_file=args.policy_file,
        secret_key=args.secret_key,
        ledger_file=args.ledger_file,
        dry_run=getattr(args, "dry_run", False),
    )
    broker = SovereignExecutionBroker(config)

    if args.command == "evaluate":
        payload = json.loads(args.payload)
        proposal = Proposal(
            action=args.action,
            proposal_type=ProposalType(args.type),
            payload=payload,
            actor=args.actor,
        )
        decision = broker.policy_engine.evaluate(proposal)
        print(f"Proposal: {args.action}")
        print(f"Severity: {decision.severity.value}")
        print(f"Allowed: {decision.allowed}")
        print(f"Reasons:")
        for reason in decision.reasons:
            print(f"  - {reason}")

    elif args.command == "execute":
        payload = json.loads(args.payload)
        proposal = Proposal(
            action=args.action,
            proposal_type=ProposalType(args.type),
            payload=payload,
            actor=args.actor,
        )
        result = broker.process_proposal(proposal)
        print(json.dumps(result, indent=2, default=str))

    elif args.command == "audit":
        trail = broker.get_audit_trail(args.proposal_id)
        print(trail)

    elif args.command == "stats":
        print(json.dumps(broker.stats, indent=2))

    elif args.command == "verify":
        valid, broken = broker.verify_ledger_integrity()
        if valid:
            print("✅ Ledger integrity: VALID")
        else:
            print(f"❌ Ledger integrity: BROKEN at entry {broken}")


if __name__ == "__main__":
    main()
