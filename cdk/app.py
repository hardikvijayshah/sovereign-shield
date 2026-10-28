#!/usr/bin/env python3
"""CDK app entry point for Sovereign Shield.

Development: ``cdk deploy --parameters AdministratorEmail=...``.
Release templates: ``python scripts/build_release.py`` sets the
``artifactBucketPrefix`` and ``releaseVersion`` context so the template reads
published artifacts and needs no CDK bootstrap.
"""

import aws_cdk as cdk
from stacks.sovereign_shield_stack import ReleaseArtifacts, SovereignShieldStack

app = cdk.App()

bucket_prefix = app.node.try_get_context("artifactBucketPrefix")
release_version = app.node.try_get_context("releaseVersion")
artifacts = ReleaseArtifacts(version=release_version, bucket_prefix=bucket_prefix) if bucket_prefix else None

SovereignShieldStack(
    app,
    "SovereignShieldStack",
    artifacts=artifacts,
    synthesizer=cdk.BootstraplessSynthesizer() if artifacts else None,
    description=(
        f"Sovereign Shield {artifacts.version} - customer-owned AWS data sovereignty assessments"
        if artifacts
        else "Sovereign Shield - customer-owned AWS data sovereignty assessments (development)"
    ),
)

app.synth()
