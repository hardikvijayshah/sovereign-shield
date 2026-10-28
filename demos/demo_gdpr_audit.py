"""Targeted GDPR compliance audit for EU regions only."""

from sovereign_shield.agents import create_orchestrator


def main():
    orchestrator = create_orchestrator()

    response = orchestrator("""
    Perform a targeted GDPR compliance audit.

    Scan only EU regions: eu-west-1, eu-central-1, eu-west-2, eu-north-1
    Regulation: GDPR only

    Focus on:
    - S3 buckets with cross-region replication rules going outside EU
    - RDS instances with read replicas in non-EU regions
    - DynamoDB global tables replicating to non-EU regions
    - CloudFront distributions serving EU-origin data to global edge locations
    - Any unencrypted resources storing personal data

    For every violation found, generate:
    1. The specific GDPR article being violated
    2. The exact AWS CLI command to fix it
    3. An SCP policy to prevent recurrence
    """)

    print(response)


if __name__ == "__main__":
    main()
