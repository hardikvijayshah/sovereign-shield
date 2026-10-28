"""Interactive session — scan first, then ask follow-up questions."""

from sovereign_shield.agents import create_orchestrator


def main():
    orchestrator = create_orchestrator()

    print("Running initial scan...\n")
    response = orchestrator(
        "Scan eu-central-1 and us-east-1 for GDPR violations. "
        "Focus on S3 and RDS cross-border data flows."
    )
    print(response)

    questions = [
        "Which of these violations are critical severity?",
        "Generate an SCP policy that blocks all S3 replication to regions outside the EU.",
        "What would a compliant architecture look like if we need read replicas for low-latency access in Asia?",
        "Summarize the top 3 actions we should take this week.",
    ]

    for q in questions:
        print(f"\n{'─' * 60}")
        print(f"Question: {q}\n")
        response = orchestrator(q)
        print(response)


if __name__ == "__main__":
    main()
