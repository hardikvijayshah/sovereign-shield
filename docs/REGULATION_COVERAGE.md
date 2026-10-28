# Regulation Coverage and Limitations

Sovereign Shield evaluates **AWS resource configuration** against data-residency
constraints derived from seven regulations. It produces evidence-backed
*potential* findings for your compliance team to validate. It does not provide
legal advice, certification, or a determination that you comply.

## What is evaluated

| Regulation | ID | Constraints evaluated |
|---|---|---|
| EU General Data Protection Regulation | `gdpr` | Personal and sensitive personal data residency in EU/EEA regions; transfers to regions outside the EU and adequacy regions; encryption at rest and in transit |
| EU Data Act | `eu-data-act` | IoT, connected-product, and industrial data residency |
| India Digital Personal Data Protection Act | `dpdp` | Personal data transfer restrictions; critical personal data must remain in India |
| China Personal Information Protection Law | `pipl` | Personal information localization in China regions |
| Brazil General Data Protection Law | `lgpd` | Personal data transfers outside Brazil |
| EU Digital Operational Resilience Act | `dora` | Financial and transaction data location for EU financial entities |
| EU NIS2 Directive | `nis2` | Critical-infrastructure and network-security data location controls |

The exact allowed, prohibited, and adequacy regions per data category are
defined in `src/sovereign_shield/regulations.py`. Each finding records the
rule ID and rule-pack version it was evaluated under.

## Services and signals

S3 (bucket region, replication destinations, default encryption), RDS
(instance and cluster read replicas), DynamoDB (global table replicas), KMS
(multi-Region key replicas), SNS (cross-region subscriptions), Transit Gateway
(inter-region peering), CloudFront and Lambda@Edge (global edge execution).

## Important limitations

1. **Data classification is yours.** Sovereign Shield cannot see what data a
   resource holds. Findings apply only to the data categories you select for
   a scan. Unselected categories are not evaluated, and every finding is marked
   `potential` with `data_classification: not_assessed`.
2. **Legal basis is not assessed.** Adequacy decisions are modelled per
   region, but transfer mechanisms such as standard contractual clauses or
   binding corporate rules are not visible in AWS configuration. A finding may
   be lawful if you rely on one.
3. **Configuration, not traffic.** Only configured data paths are found:
   replication, replicas, peering, subscriptions, and edge distribution.
   Application-level transfers (for example, an API call that copies data to
   another region) are not observed.
4. **Coverage gaps are not clean results.** A service or region that could not
   be read (permissions, opt-in region, throttling) appears as a coverage gap.
   Absence of findings there means "not assessed", not "compliant".
5. **Regions not in the AWS commercial partition** (GovCloud, China) are not
   supported by this release.
6. **Regulations change.** Rule-pack versions are recorded on each finding.
   Review results against the current legal text before acting.
