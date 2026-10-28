"""Unit tests for the supported AWS discovery scanners.

These tests use small, service-shaped fakes rather than AWS credentials. They
protect the normalized payload contract consumed by the direct scan engine.
"""

from __future__ import annotations

import json
from typing import Any

from sovereign_shield.tools import aws_scanner
from sovereign_shield.tools.invocation import invoke_tool


class _Paginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_: Any) -> list[dict[str, Any]]:
        return self._pages


def _scan(monkeypatch, scanner: Any, client: Any) -> dict[str, Any]:
    monkeypatch.setattr(aws_scanner, "_get_client", lambda *_args, **_kwargs: client)
    response = invoke_tool(scanner, region="eu-central-1", account_id="")
    return json.loads(response)


def test_s3_scanner_emits_encrypted_resource_and_replication_flow(monkeypatch):
    class S3Client:
        class exceptions:
            ClientError = Exception

        def list_buckets(self):
            return {"Buckets": [{"Name": "source-bucket"}]}

        def get_bucket_location(self, *, Bucket):
            return {"LocationConstraint": "eu-central-1" if Bucket == "source-bucket" else "us-east-1"}

        def get_bucket_encryption(self, **_):
            return {"ServerSideEncryptionConfiguration": {"Rules": [{}]}}

        def get_bucket_replication(self, **_):
            return {
                "ReplicationConfiguration": {
                    "Rules": [{"ID": "replicate", "Destination": {"Bucket": "arn:aws:s3:::destination-bucket"}}]
                }
            }

    result = _scan(monkeypatch, aws_scanner.scan_s3_buckets, S3Client())

    assert result["resources"][0]["encryption_at_rest"] is True
    assert result["flows"][0]["destination_regions"] == ["us-east-1"]
    assert result["flows"][0]["flow_type"] == "replication"


def test_rds_scanner_emits_instance_and_cluster_replica_flows(monkeypatch):
    class RdsClient:
        def get_paginator(self, name):
            pages = {
                "describe_db_instances": [
                    {
                        "DBInstances": [
                            {
                                "DBInstanceArn": "arn:aws:rds:eu-central-1:123:db:primary",
                                "DBInstanceIdentifier": "primary",
                                "StorageEncrypted": True,
                                "ReadReplicaDBInstanceIdentifiers": ["arn:aws:rds:us-east-1:123:db:replica"],
                            }
                        ]
                    }
                ],
                "describe_db_clusters": [
                    {
                        "DBClusters": [
                            {
                                "DBClusterArn": "arn:aws:rds:eu-central-1:123:cluster:primary",
                                "DBClusterIdentifier": "primary-cluster",
                                "StorageEncrypted": True,
                                "ReadReplicaIdentifiers": ["arn:aws:rds:us-west-2:123:cluster:replica"],
                            }
                        ]
                    }
                ],
            }
            return _Paginator(pages[name])

    result = _scan(monkeypatch, aws_scanner.scan_rds_instances, RdsClient())

    assert len(result["resources"]) == 2
    assert {flow["destination_regions"][0] for flow in result["flows"]} == {"us-east-1", "us-west-2"}


def test_dynamodb_scanner_emits_global_table_replica_flow(monkeypatch):
    class DynamoDbClient:
        def get_paginator(self, _):
            return _Paginator([{"TableNames": ["customers"]}])

        def describe_table(self, **_):
            return {
                "Table": {
                    "TableArn": "arn:aws:dynamodb:eu-central-1:123:table/customers",
                    "SSEDescription": {"Status": "ENABLED"},
                    "Replicas": [{"RegionName": "eu-central-1"}, {"RegionName": "us-east-1"}],
                }
            }

    result = _scan(monkeypatch, aws_scanner.scan_dynamodb_tables, DynamoDbClient())

    assert result["resources"][0]["encryption_at_rest"] is True
    assert result["flows"][0]["destination_regions"] == ["us-east-1"]


def test_cloudfront_scanner_emits_global_edge_cache_flow(monkeypatch):
    class CloudFrontClient:
        def get_paginator(self, _):
            return _Paginator(
                [
                    {
                        "DistributionList": {
                            "Items": [
                                {
                                    "Id": "distribution-id",
                                    "ARN": "arn:aws:cloudfront::123:distribution/distribution-id",
                                    "Origins": {"Items": [{"DomainName": "service.eu-central-1.example.com"}]},
                                    "PriceClass": "PriceClass_100",
                                    "ViewerCertificate": {"SSLSupportMethod": "sni-only"},
                                }
                            ]
                        }
                    }
                ]
            )

    result = _scan(monkeypatch, aws_scanner.scan_cloudfront_distributions, CloudFrontClient())

    assert result["resources"][0]["region"] == "global"
    assert result["flows"][0]["flow_type"] == "edge_cache"
    assert "eu-west-1" in result["flows"][0]["destination_regions"]


def test_kms_scanner_emits_multi_region_key_replica_flow(monkeypatch):
    class KmsClient:
        def get_paginator(self, _):
            return _Paginator([{"Keys": [{"KeyId": "key-id"}]}])

        def describe_key(self, **_):
            return {
                "KeyMetadata": {
                    "KeyManager": "CUSTOMER",
                    "Arn": "arn:aws:kms:eu-central-1:123:key/key-id",
                    "KeySpec": "SYMMETRIC_DEFAULT",
                    "MultiRegion": True,
                    "MultiRegionConfiguration": {"ReplicaKeys": [{"Region": "us-east-1"}]},
                }
            }

    result = _scan(monkeypatch, aws_scanner.scan_kms_keys, KmsClient())

    assert result["resources"][0]["service"] == "KMS"
    assert result["flows"][0]["encryption_enabled"] is True
    assert result["flows"][0]["destination_regions"] == ["us-east-1"]


def test_sns_scanner_emits_cross_region_subscription_flow(monkeypatch):
    class SnsClient:
        def get_paginator(self, name):
            pages = {
                "list_topics": [{"Topics": [{"TopicArn": "arn:aws:sns:eu-central-1:123:events"}]}],
                "list_subscriptions_by_topic": [
                    {
                        "Subscriptions": [
                            {
                                "Protocol": "sqs",
                                "Endpoint": "arn:aws:sqs:us-east-1:123:events",
                            }
                        ]
                    }
                ],
            }
            return _Paginator(pages[name])

        def get_topic_attributes(self, **_):
            return {"Attributes": {"KmsMasterKeyId": "alias/events"}}

    result = _scan(monkeypatch, aws_scanner.scan_sns_sqs, SnsClient())

    assert result["resources"][0]["service"] == "SNS"
    assert result["flows"][0]["flow_type"] == "stream"
    assert result["flows"][0]["destination_regions"] == ["us-east-1"]


def test_transit_gateway_scanner_emits_peering_flow(monkeypatch):
    class Ec2Client:
        def describe_transit_gateways(self):
            return {
                "TransitGateways": [
                    {
                        "TransitGatewayId": "tgw-123",
                        "TransitGatewayArn": "arn:aws:ec2:eu-central-1:123:transit-gateway/tgw-123",
                    }
                ]
            }

        def describe_transit_gateway_peering_attachments(self, **_):
            return {
                "TransitGatewayPeeringAttachments": [
                    {
                        "TransitGatewayAttachmentId": "tgw-attach-123",
                        "AccepterTgwInfo": {"Region": "us-east-1"},
                    }
                ]
            }

    result = _scan(monkeypatch, aws_scanner.scan_transit_gateways, Ec2Client())

    assert result["resources"][0]["service"] == "TransitGateway"
    assert result["flows"][0]["flow_type"] == "peering"
    assert result["flows"][0]["destination_regions"] == ["us-east-1"]


def test_lambda_at_edge_scanner_emits_global_execution_flow(monkeypatch):
    class LambdaClient:
        def get_paginator(self, _):
            return _Paginator(
                [
                    {
                        "Functions": [
                            {
                                "FunctionArn": "arn:aws:lambda:us-east-1:123:function:edge-handler",
                                "FunctionName": "edge-handler",
                                "Runtime": "python3.13",
                            }
                        ]
                    }
                ]
            )

        def get_policy(self, **_):
            return {
                "Policy": json.dumps(
                    {"Statement": [{"Principal": {"Service": "edgelambda.amazonaws.com"}}]}
                )
            }

    result = _scan(monkeypatch, aws_scanner.scan_lambda_at_edge, LambdaClient())

    assert result["resources"][0]["details"]["edge_function"] is True
    assert result["flows"][0]["destination_regions"] == ["global-edge-locations"]


class _RecordingBoto3:
    def __init__(self) -> None:
        self.clients: list[tuple[str, dict[str, Any]]] = []

    def client(self, service: str, **kwargs: Any) -> Any:
        self.clients.append((service, kwargs))
        recorder = self

        class _Sts:
            def assume_role(self, **kwargs: Any) -> dict[str, Any]:
                recorder.clients.append(("assume_role", kwargs))
                from datetime import datetime, timedelta, timezone

                return {"Credentials": {
                    "AccessKeyId": "a", "SecretAccessKey": "s", "SessionToken": "t",
                    "Expiration": datetime.now(timezone.utc) + timedelta(hours=1),
                }}

        return _Sts() if service == "sts" else object()


def test_deployment_account_is_scanned_without_assuming_a_member_role(monkeypatch):
    fake = _RecordingBoto3()
    monkeypatch.setattr(aws_scanner, "boto3", fake)
    monkeypatch.setenv("DEPLOYMENT_ACCOUNT_ID", "111111111111")

    aws_scanner._get_client("s3", "eu-central-1", "111111111111")

    assert fake.clients == [("s3", {"region_name": "eu-central-1"})]


def test_other_accounts_are_scanned_through_the_member_role(monkeypatch):
    fake = _RecordingBoto3()
    monkeypatch.setattr(aws_scanner, "boto3", fake)
    monkeypatch.setattr(aws_scanner, "_assumed_credentials", {})
    monkeypatch.setenv("DEPLOYMENT_ACCOUNT_ID", "111111111111")
    monkeypatch.delenv("SCAN_ROLE_EXTERNAL_ID", raising=False)
    monkeypatch.delenv("SCAN_ROLE_NAME", raising=False)

    aws_scanner._get_client("s3", "eu-central-1", "222222222222")

    assert ("assume_role", {
        "RoleArn": "arn:aws:iam::222222222222:role/SovereignShieldScanRole",
        "RoleSessionName": "sovereign-shield-111111111111",
    }) in fake.clients


def test_member_role_calls_send_the_installation_external_id_and_role_name(monkeypatch):
    fake = _RecordingBoto3()
    monkeypatch.setattr(aws_scanner, "boto3", fake)
    monkeypatch.setattr(aws_scanner, "_assumed_credentials", {})
    monkeypatch.setenv("DEPLOYMENT_ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("SCAN_ROLE_EXTERNAL_ID", "4a6e7810-d118-11f1-abd8-0afff2ee5fb3")
    monkeypatch.setenv("SCAN_ROLE_NAME", "SovereignShieldScanRole-prod")

    aws_scanner._get_client("kms", "eu-west-1", "222222222222")

    assume = next(kwargs for name, kwargs in fake.clients if name == "assume_role")
    assert assume["ExternalId"] == "4a6e7810-d118-11f1-abd8-0afff2ee5fb3"
    assert assume["RoleArn"] == "arn:aws:iam::222222222222:role/SovereignShieldScanRole-prod"


def test_member_role_credentials_are_reused_until_near_expiry(monkeypatch):
    fake = _RecordingBoto3()
    monkeypatch.setattr(aws_scanner, "boto3", fake)
    monkeypatch.setattr(aws_scanner, "_assumed_credentials", {})
    monkeypatch.setenv("DEPLOYMENT_ACCOUNT_ID", "111111111111")

    aws_scanner._get_client("s3", "eu-central-1", "222222222222")
    aws_scanner._get_client("rds", "eu-west-1", "222222222222")
    assert sum(name == "assume_role" for name, _ in fake.clients) == 1

    from datetime import datetime, timedelta, timezone

    aws_scanner._assumed_credentials["222222222222"]["Expiration"] = datetime.now(timezone.utc) + timedelta(minutes=2)
    aws_scanner._get_client("rds", "eu-west-1", "222222222222")
    assert sum(name == "assume_role" for name, _ in fake.clients) == 2
