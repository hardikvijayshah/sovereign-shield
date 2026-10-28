"""Full sovereignty compliance scan across multiple regions and regulations."""

from sovereign_shield.agents import create_orchestrator


def main():
    orchestrator = create_orchestrator()

    print("=" * 70)
    print("  SOVEREIGN SHIELD — Full Compliance Scan Demo")
    print("=" * 70)

    response = orchestrator("""
    Run a complete sovereignty compliance scan on the following environment:

    AWS Regions: eu-west-1, eu-central-1, us-east-1, ap-south-1
    Regulations: GDPR, DPDP, DORA

    Our organization operates in Europe and India. We store:
    - Customer personal data (PII) in eu-central-1
    - Financial transaction data in eu-west-1
    - Application backups in us-east-1
    - Indian customer data in ap-south-1

    Execute the full pipeline:
    1) Profile applicable jurisdictions
    2) Scan all resources for cross-border data flows
    3) Detect violations
    4) Generate remediation plans with SCP policies
    5) Produce the executive Sovereignty Posture Report
    """)

    print(response)

    with open("sovereignty_report.md", "w") as f:
        f.write(str(response))
    print("\nReport saved to sovereignty_report.md")


if __name__ == "__main__":
    main()
