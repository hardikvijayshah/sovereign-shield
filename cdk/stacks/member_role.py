"""Member-account scan role template (plan.md sections 7.2 and 8.1).

One builder produces both the template the central stack's StackSet deploys
into member accounts and the standalone ``sovereign-shield-member-role.yaml``
release artifact, so the two can never drift apart.

The role is read-only and trusted only by the exact central role ARNs, with
this installation's external ID, from principals inside the organization.
"""

from __future__ import annotations

from typing import Any

# Read-only discovery actions used by `tools/aws_scanner.py`, shared by the central
# scan worker and every member role. These List and Describe APIs do not support
# resource-level permissions, so `*` is required.
SCANNER_READ_ACTIONS = [
    "s3:ListAllMyBuckets",
    "s3:GetBucketLocation",
    "s3:GetEncryptionConfiguration",
    "s3:GetReplicationConfiguration",
    "rds:DescribeDBInstances",
    "rds:DescribeDBClusters",
    "dynamodb:ListTables",
    "dynamodb:DescribeTable",
    "cloudfront:ListDistributions",
    "kms:ListKeys",
    "kms:DescribeKey",
    "sns:ListTopics",
    "sns:GetTopicAttributes",
    "sns:ListSubscriptionsByTopic",
    "ec2:DescribeTransitGateways",
    "ec2:DescribeTransitGatewayPeeringAttachments",
    "lambda:ListFunctions",
    "lambda:GetPolicy",
    "lambda:ListTags",
]


def member_role_template() -> dict[str, Any]:
    """CloudFormation template for the read-only member scan role."""

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Sovereign Shield read-only member scan role, trusted only by one central installation.",
        "Parameters": {
            "CentralPrincipalArns": {
                "Type": "CommaDelimitedList",
                "Description": "Exact ARNs of the central Sovereign Shield roles allowed to assume this role.",
            },
            "ExternalId": {
                "Type": "String",
                "MinLength": 2,
                "MaxLength": 1224,
                "AllowedPattern": r"^[\w+=,.@:/-]+$",
                "Description": "The central installation's external ID (stack output MemberRoleExternalId).",
            },
            "OrganizationId": {
                "Type": "String",
                "AllowedPattern": r"^o-[a-z0-9]{10,32}$",
                "Description": "Only principals in this organization may assume the role.",
            },
            "RoleName": {
                "Type": "String",
                "Default": "SovereignShieldScanRole",
                "AllowedPattern": r"^[\w+=,.@-]{1,64}$",
                "Description": "Must match the central stack's MemberRoleName parameter.",
            },
        },
        "Resources": {
            "SovereignShieldScanRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "RoleName"},
                    "Description": "Read-only discovery for Sovereign Shield. Cannot modify resources.",
                    "MaxSessionDuration": 3600,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "CentralSovereignShieldOnly",
                            "Effect": "Allow",
                            "Principal": {"AWS": {"Ref": "CentralPrincipalArns"}},
                            "Action": "sts:AssumeRole",
                            "Condition": {
                                "StringEquals": {
                                    "sts:ExternalId": {"Ref": "ExternalId"},
                                    "aws:PrincipalOrgID": {"Ref": "OrganizationId"},
                                },
                            },
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "SovereignShieldReadOnlyDiscovery",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Sid": "ReadOnlyDiscovery",
                                "Effect": "Allow",
                                "Action": SCANNER_READ_ACTIONS,
                                "Resource": "*",
                            }],
                        },
                    }],
                    "Tags": [{"Key": "Application", "Value": "SovereignShield"}],
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["SovereignShieldScanRole", "Arn"]}},
        },
    }
