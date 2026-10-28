"""Strands agent tools for scanning AWS resources for cross-border data flows."""

from __future__ import annotations

import json
import logging
import os
import time

import boto3

from sovereign_shield.tools.invocation import tool

logger = logging.getLogger(__name__)


_CREDENTIAL_REFRESH_MARGIN_SECONDS = 300
_assumed_credentials: dict[str, dict] = {}


def member_role_credentials(account_id: str) -> dict:
    """Assume the member scan role in ``account_id``; cached until shortly before expiry.

    The role name and per-installation external ID come from the stack
    (``SCAN_ROLE_NAME`` / ``SCAN_ROLE_EXTERNAL_ID``). Every call sends the
    external ID when one is configured, matching the member role's trust policy.
    """

    cached = _assumed_credentials.get(account_id)
    if cached and cached["Expiration"].timestamp() - time.time() > _CREDENTIAL_REFRESH_MARGIN_SECONDS:
        return cached
    request = {
        "RoleArn": f"arn:aws:iam::{account_id}:role/{os.environ.get('SCAN_ROLE_NAME', 'SovereignShieldScanRole')}",
        "RoleSessionName": f"sovereign-shield-{os.environ.get('DEPLOYMENT_ACCOUNT_ID', 'scan')}",
    }
    external_id = os.environ.get("SCAN_ROLE_EXTERNAL_ID")
    if external_id:
        request["ExternalId"] = external_id
    # Regional STS endpoint: credential requests stay in the stack's region.
    sts = boto3.client("sts", region_name=os.environ.get("AWS_REGION"),
                       endpoint_url=_regional_sts_endpoint(os.environ.get("AWS_REGION")))
    credentials = sts.assume_role(**request)["Credentials"]
    _assumed_credentials[account_id] = credentials
    return credentials


def _regional_sts_endpoint(region: str | None) -> str | None:
    return f"https://sts.{region}.amazonaws.com" if region else None


def _get_client(service: str, region: str, account_id: str | None = None):
    """Get a boto3 client, optionally assuming a cross-account role.

    The deployment account is scanned with the function's own credentials;
    only other accounts require the member scan role.
    """
    if account_id and account_id != os.environ.get("DEPLOYMENT_ACCOUNT_ID"):
        creds = member_role_credentials(account_id)
        return boto3.client(
            service,
            region_name=region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return boto3.client(service, region_name=region)


@tool
def scan_s3_buckets(region: str, account_id: str = "") -> str:
    """Scan S3 buckets in a region for cross-region replication rules and server-side encryption settings.

    Args:
        region: AWS region to scan (e.g., eu-west-1)
        account_id: AWS account ID for cross-account scanning (optional)
    """
    s3 = _get_client("s3", region, account_id or None)
    flows = []
    resources = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            except Exception:
                continue

            if loc != region:
                continue

            encryption = False
            try:
                enc_config = s3.get_bucket_encryption(Bucket=name)
                encryption = bool(enc_config.get("ServerSideEncryptionConfiguration", {}).get("Rules"))
            except s3.exceptions.ClientError:
                pass

            resources.append({
                "service": "S3",
                "resource_name": name,
                "resource_arn": f"arn:aws:s3:::{name}",
                "region": loc,
                "encryption_at_rest": encryption,
            })

            try:
                replication = s3.get_bucket_replication(Bucket=name)
                for rule in replication.get("ReplicationConfiguration", {}).get("Rules", []):
                    dest = rule.get("Destination", {})
                    dest_bucket = dest.get("Bucket", "")
                    dest_region = dest.get("StorageClass", "")

                    try:
                        dest_loc_resp = s3.get_bucket_location(
                            Bucket=dest_bucket.split(":::")[-1]
                        )
                        dest_region = dest_loc_resp.get("LocationConstraint") or "us-east-1"
                    except Exception:
                        pass

                    if dest_region and dest_region != loc:
                        flows.append({
                            "service": "S3",
                            "resource_name": name,
                            "resource_arn": f"arn:aws:s3:::{name}",
                            "source_region": loc,
                            "destination_regions": [dest_region],
                            "flow_type": "replication",
                            "encryption_enabled": bool(dest.get("EncryptionConfiguration")),
                            "details": {"rule_id": rule.get("ID", ""), "destination_bucket": dest_bucket},
                        })
            except s3.exceptions.ClientError:
                pass

    except Exception as e:
        return json.dumps({"error": str(e), "resources": [], "flows": []})

    return json.dumps({"resources": resources, "flows": flows})


@tool
def scan_rds_instances(region: str, account_id: str = "") -> str:
    """Scan RDS instances and clusters for cross-region read replicas and automated backups.

    Args:
        region: AWS region to scan
        account_id: AWS account ID for cross-account scanning (optional)
    """
    rds = _get_client("rds", region, account_id or None)
    flows = []
    resources = []

    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                arn = db["DBInstanceArn"]
                resources.append({
                    "service": "RDS",
                    "resource_name": db["DBInstanceIdentifier"],
                    "resource_arn": arn,
                    "region": region,
                    "encryption_at_rest": db.get("StorageEncrypted", False),
                    "details": {"engine": db.get("Engine"), "multi_az": db.get("MultiAZ", False)},
                })

                for replica_arn in db.get("ReadReplicaDBInstanceIdentifiers", []):
                    replica_region = replica_arn.split(":")[3] if ":" in replica_arn else ""
                    if replica_region and replica_region != region:
                        flows.append({
                            "service": "RDS",
                            "resource_name": db["DBInstanceIdentifier"],
                            "resource_arn": arn,
                            "source_region": region,
                            "destination_regions": [replica_region],
                            "flow_type": "replication",
                            "encryption_enabled": db.get("StorageEncrypted", False),
                            "details": {"replica_arn": replica_arn},
                        })

        cluster_paginator = rds.get_paginator("describe_db_clusters")
        for page in cluster_paginator.paginate():
            for cluster in page["DBClusters"]:
                arn = cluster["DBClusterArn"]
                resources.append({
                    "service": "RDS",
                    "resource_name": cluster["DBClusterIdentifier"],
                    "resource_arn": arn,
                    "region": region,
                    "encryption_at_rest": cluster.get("StorageEncrypted", False),
                    "details": {"engine": cluster.get("Engine")},
                })

                for replica_id in cluster.get("ReadReplicaIdentifiers", []):
                    replica_region = replica_id.split(":")[3] if ":" in replica_id else ""
                    if replica_region and replica_region != region:
                        flows.append({
                            "service": "RDS",
                            "resource_name": cluster["DBClusterIdentifier"],
                            "resource_arn": arn,
                            "source_region": region,
                            "destination_regions": [replica_region],
                            "flow_type": "replication",
                            "encryption_enabled": cluster.get("StorageEncrypted", False),
                        })

    except Exception as e:
        return json.dumps({"error": str(e), "resources": [], "flows": []})

    return json.dumps({"resources": resources, "flows": flows})


@tool
def scan_dynamodb_tables(region: str, account_id: str = "") -> str:
    """Scan DynamoDB tables for global table replicas (cross-region replication).

    Args:
        region: AWS region to scan
        account_id: AWS account ID for cross-account scanning (optional)
    """
    ddb = _get_client("dynamodb", region, account_id or None)
    flows = []
    resources = []

    try:
        paginator = ddb.get_paginator("list_tables")
        for page in paginator.paginate():
            for table_name in page["TableNames"]:
                desc = ddb.describe_table(TableName=table_name)["Table"]
                arn = desc["TableArn"]

                encryption = False
                sse = desc.get("SSEDescription", {})
                if sse.get("Status") == "ENABLED":
                    encryption = True

                resources.append({
                    "service": "DynamoDB",
                    "resource_name": table_name,
                    "resource_arn": arn,
                    "region": region,
                    "encryption_at_rest": encryption,
                })

                replicas = desc.get("Replicas", [])
                replica_regions = [r["RegionName"] for r in replicas if r["RegionName"] != region]
                if replica_regions:
                    flows.append({
                        "service": "DynamoDB",
                        "resource_name": table_name,
                        "resource_arn": arn,
                        "source_region": region,
                        "destination_regions": replica_regions,
                        "flow_type": "replication",
                        "encryption_enabled": encryption,
                        "details": {"global_table": True},
                    })

    except Exception as e:
        return json.dumps({"error": str(e), "resources": [], "flows": []})

    return json.dumps({"resources": resources, "flows": flows})


@tool
def scan_cloudfront_distributions(region: str, account_id: str = "") -> str:
    """Scan CloudFront distributions to identify edge cache locations that serve data globally.

    Args:
        region: AWS region (CloudFront is global, but we report per calling region)
        account_id: AWS account ID for cross-account scanning (optional)
    """
    cf = _get_client("cloudfront", "us-east-1", account_id or None)
    flows = []
    resources = []

    try:
        paginator = cf.get_paginator("list_distributions")
        for page in paginator.paginate():
            dist_list = page.get("DistributionList", {})
            for dist in dist_list.get("Items", []):
                dist_id = dist["Id"]
                arn = dist["ARN"]
                origins = dist.get("Origins", {}).get("Items", [])
                origin_regions = set()
                for origin in origins:
                    domain = origin.get("DomainName", "")
                    for r in ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-south-1", "ap-southeast-1"]:
                        if r in domain:
                            origin_regions.add(r)

                price_class = dist.get("PriceClass", "PriceClass_All")
                edge_regions = _price_class_to_regions(price_class)

                resources.append({
                    "service": "CloudFront",
                    "resource_name": dist_id,
                    "resource_arn": arn,
                    "region": "global",
                    "details": {"price_class": price_class, "origins": [o.get("DomainName") for o in origins]},
                })

                for origin_region in origin_regions:
                    non_origin_edges = [r for r in edge_regions if r != origin_region]
                    if non_origin_edges:
                        flows.append({
                            "service": "CloudFront",
                            "resource_name": dist_id,
                            "resource_arn": arn,
                            "source_region": origin_region,
                            "destination_regions": non_origin_edges,
                            "flow_type": "edge_cache",
                            "encryption_enabled": dist.get("ViewerCertificate", {}).get("SSLSupportMethod") is not None,
                            "details": {"price_class": price_class},
                        })

    except Exception as e:
        return json.dumps({"error": str(e), "resources": [], "flows": []})

    return json.dumps({"resources": resources, "flows": flows})


def _price_class_to_regions(price_class: str) -> list[str]:
    if price_class == "PriceClass_100":
        return ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ca-central-1"]
    elif price_class == "PriceClass_200":
        return [
            "us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
            "ca-central-1", "ap-southeast-1", "ap-northeast-1", "ap-south-1",
        ]
    return [
        "us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ca-central-1",
        "ap-southeast-1", "ap-northeast-1", "ap-south-1", "sa-east-1",
        "af-south-1", "me-south-1",
    ]


@tool
def scan_kms_keys(region: str, account_id: str = "") -> str:
    """Scan KMS keys to identify multi-region keys that replicate across regions.

    Args:
        region: AWS region to scan
        account_id: AWS account ID for cross-account scanning (optional)
    """
    kms = _get_client("kms", region, account_id or None)
    flows = []
    resources = []

    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key_entry in page["Keys"]:
                key_id = key_entry["KeyId"]
                try:
                    key_meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                except Exception:
                    continue

                if key_meta.get("KeyManager") == "AWS":
                    continue

                arn = key_meta["Arn"]
                resources.append({
                    "service": "KMS",
                    "resource_name": key_id,
                    "resource_arn": arn,
                    "region": region,
                    "details": {"key_spec": key_meta.get("KeySpec"), "multi_region": key_meta.get("MultiRegion")},
                })

                if key_meta.get("MultiRegion"):
                    mr_config = key_meta.get("MultiRegionConfiguration", {})
                    replica_keys = mr_config.get("ReplicaKeys", [])
                    replica_regions = [rk["Region"] for rk in replica_keys if rk["Region"] != region]
                    if replica_regions:
                        flows.append({
                            "service": "KMS",
                            "resource_name": key_id,
                            "resource_arn": arn,
                            "source_region": region,
                            "destination_regions": replica_regions,
                            "flow_type": "replication",
                            "encryption_enabled": True,
                        })

    except Exception as e:
        return json.dumps({"error": str(e), "resources": [], "flows": []})

    return json.dumps({"resources": resources, "flows": flows})


@tool
def scan_sns_sqs(region: str, account_id: str = "") -> str:
    """Scan SNS topics and SQS queues for cross-region subscriptions and message forwarding.

    Args:
        region: AWS region to scan
        account_id: AWS account ID for cross-account scanning (optional)
    """
    sns = _get_client("sns", region, account_id or None)
    flows = []
    resources = []

    try:
        paginator = sns.get_paginator("list_topics")
        for page in paginator.paginate():
            for topic in page["Topics"]:
                topic_arn = topic["TopicArn"]
                topic_name = topic_arn.split(":")[-1]

                try:
                    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
                except Exception:
                    continue

                kms_key = attrs.get("KmsMasterKeyId", "")
                resources.append({
                    "service": "SNS",
                    "resource_name": topic_name,
                    "resource_arn": topic_arn,
                    "region": region,
                    "encryption_at_rest": bool(kms_key),
                })

                sub_paginator = sns.get_paginator("list_subscriptions_by_topic")
                for sub_page in sub_paginator.paginate(TopicArn=topic_arn):
                    for sub in sub_page["Subscriptions"]:
                        endpoint = sub.get("Endpoint", "")
                        if ":sqs:" in endpoint or ":lambda:" in endpoint:
                            endpoint_region = endpoint.split(":")[3] if ":" in endpoint else ""
                            if endpoint_region and endpoint_region != region:
                                flows.append({
                                    "service": "SNS",
                                    "resource_name": topic_name,
                                    "resource_arn": topic_arn,
                                    "source_region": region,
                                    "destination_regions": [endpoint_region],
                                    "flow_type": "stream",
                                    "encryption_enabled": bool(kms_key),
                                    "details": {"subscription_protocol": sub.get("Protocol"), "endpoint": endpoint},
                                })

    except Exception as e:
        return json.dumps({"error": str(e), "resources": [], "flows": []})

    return json.dumps({"resources": resources, "flows": flows})


@tool
def scan_transit_gateways(region: str, account_id: str = "") -> str:
    """Scan Transit Gateway peering attachments for cross-region network data flows.

    Args:
        region: AWS region to scan
        account_id: AWS account ID for cross-account scanning (optional)
    """
    ec2 = _get_client("ec2", region, account_id or None)
    flows = []
    resources = []

    try:
        tgws = ec2.describe_transit_gateways().get("TransitGateways", [])
        for tgw in tgws:
            tgw_id = tgw["TransitGatewayId"]
            arn = tgw.get("TransitGatewayArn", "")
            resources.append({
                "service": "TransitGateway",
                "resource_name": tgw_id,
                "resource_arn": arn,
                "region": region,
            })

            attachments = ec2.describe_transit_gateway_peering_attachments(
                Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
            ).get("TransitGatewayPeeringAttachments", [])

            for att in attachments:
                peer_region = att.get("AccepterTgwInfo", {}).get("Region", "")
                if peer_region and peer_region != region:
                    flows.append({
                        "service": "TransitGateway",
                        "resource_name": tgw_id,
                        "resource_arn": arn,
                        "source_region": region,
                        "destination_regions": [peer_region],
                        "flow_type": "peering",
                        "encryption_enabled": False,
                        "details": {"attachment_id": att.get("TransitGatewayAttachmentId")},
                    })

    except Exception as e:
        return json.dumps({"error": str(e), "resources": [], "flows": []})

    return json.dumps({"resources": resources, "flows": flows})


@tool
def scan_lambda_at_edge(region: str, account_id: str = "") -> str:
    """Scan Lambda@Edge functions that execute at CloudFront edge locations globally.

    Args:
        region: AWS region to scan (Lambda@Edge must be in us-east-1)
        account_id: AWS account ID for cross-account scanning (optional)
    """
    lam = _get_client("lambda", "us-east-1", account_id or None)
    flows = []
    resources = []

    try:
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for func in page["Functions"]:
                arn = func["FunctionArn"]
                func_name = func["FunctionName"]

                try:
                    policy = json.loads(lam.get_policy(FunctionName=func_name)["Policy"])
                    is_edge = any(
                        stmt.get("Principal", {}).get("Service") == "edgelambda.amazonaws.com"
                        or "edgelambda" in json.dumps(stmt)
                        for stmt in policy.get("Statement", [])
                    )
                except Exception:
                    is_edge = False

                if not is_edge:
                    try:
                        tags = lam.list_tags(Resource=arn).get("Tags", {})
                        is_edge = tags.get("aws:cloudfront:distribution-id") is not None
                    except Exception:
                        pass

                if is_edge:
                    resources.append({
                        "service": "Lambda@Edge",
                        "resource_name": func_name,
                        "resource_arn": arn,
                        "region": "us-east-1",
                        "details": {"runtime": func.get("Runtime"), "edge_function": True},
                    })

                    flows.append({
                        "service": "Lambda@Edge",
                        "resource_name": func_name,
                        "resource_arn": arn,
                        "source_region": "us-east-1",
                        "destination_regions": ["global-edge-locations"],
                        "flow_type": "edge_cache",
                        "encryption_enabled": True,
                        "details": {"executes_at_all_cloudfront_edge_locations": True},
                    })

    except Exception as e:
        return json.dumps({"error": str(e), "resources": [], "flows": []})

    return json.dumps({"resources": resources, "flows": flows})
