"""CLI entry point for running Sovereign Shield locally."""

from __future__ import annotations

import argparse
import os
import sys

from sovereign_shield.agents.orchestrator import create_orchestrator


def main():
    parser = argparse.ArgumentParser(
        description="Sovereign Shield — AI agent for AWS data sovereignty compliance"
    )
    parser.add_argument(
        "--accounts",
        default=os.environ.get("SCAN_ACCOUNTS", ""),
        help="Comma-separated AWS account IDs to scan",
    )
    parser.add_argument(
        "--regions",
        default=os.environ.get("SCAN_REGIONS", "us-east-1,eu-west-1,eu-central-1,ap-south-1"),
        help="Comma-separated AWS regions to scan",
    )
    parser.add_argument(
        "--regulations",
        default="",
        help="Comma-separated regulation IDs to check (empty = all). Options: gdpr,dpdp,pipl,lgpd,dora,nis2",
    )
    parser.add_argument(
        "--model-id",
        default=os.environ.get("BEDROCK_MODEL_ID"),
        help="Bedrock model ID",
    )
    parser.add_argument(
        "--model-region",
        default=os.environ.get("BEDROCK_REGION", "us-east-1"),
        help="AWS region for Bedrock API calls",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive chat mode after the initial scan",
    )
    args = parser.parse_args()

    orchestrator = create_orchestrator(
        model_id=args.model_id,
        region=args.model_region,
    )

    scan_prompt = _build_scan_prompt(args.accounts, args.regions, args.regulations)
    print(f"\n{'='*60}")
    print("  Sovereign Shield — Data Sovereignty Compliance Scanner")
    print(f"{'='*60}\n")
    print(f"Scanning regions: {args.regions}")
    if args.accounts:
        print(f"Scanning accounts: {args.accounts}")
    if args.regulations:
        print(f"Checking regulations: {args.regulations}")
    print()

    response = orchestrator(scan_prompt)
    print(f"\n{response}\n")

    if args.interactive:
        print(f"\n{'='*60}")
        print("  Interactive Mode — ask follow-up questions (Ctrl+C to exit)")
        print(f"{'='*60}\n")
        while True:
            try:
                user_input = input("You: ").strip()
                if not user_input:
                    continue
                if user_input.lower() in ("exit", "quit"):
                    break
                response = orchestrator(user_input)
                print(f"\n{response}\n")
            except (KeyboardInterrupt, EOFError):
                print("\nExiting.")
                break

    return 0


def _build_scan_prompt(accounts: str, regions: str, regulations: str) -> str:
    parts = [
        "Run a complete sovereignty compliance scan on the following AWS environment:",
        f"\nRegions to scan: {regions}",
    ]
    if accounts:
        parts.append(f"AWS Accounts: {accounts}")
    if regulations:
        parts.append(f"Regulations to check: {regulations}")
    else:
        parts.append("Check against ALL known regulations (GDPR, EU Data Act, DPDP, PIPL, LGPD, DORA, NIS2)")

    parts.append(
        "\nExecute the full pipeline: "
        "1) Profile applicable jurisdictions, "
        "2) Scan all resources for cross-border data flows, "
        "3) Detect violations, "
        "4) Generate remediation plans with SCP policies, "
        "5) Produce the executive Sovereignty Posture Report."
    )
    return "\n".join(parts)


if __name__ == "__main__":
    sys.exit(main())
