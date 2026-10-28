"""Persistence ports and adapters for deterministic scan evidence and findings."""

from __future__ import annotations

import base64
import copy
import json
import time
import uuid
from typing import Any, Protocol

from sovereign_shield.models.contracts import DeterministicScanResult, EvaluationResult


class ScanStore(Protocol):
    """Storage boundary shared by direct workers and future workflow handlers."""

    def save_scan_result(self, result: DeterministicScanResult) -> None:
        """Persist normalized scan metadata, evidence, and coverage gaps."""

    def save_evaluation(self, result: EvaluationResult) -> None:
        """Persist deterministic findings for an existing scan run."""


class InMemoryScanStore:
    """Deterministic test adapter; not intended for a customer deployment."""

    def __init__(self) -> None:
        self.runs: dict[str, dict[str, Any]] = {}
        self.evidence: dict[str, list[dict[str, Any]]] = {}
        self.coverage_gaps: dict[str, list[dict[str, Any]]] = {}
        self.findings: dict[str, list[dict[str, Any]]] = {}

    def save_scan_result(self, result: DeterministicScanResult) -> None:
        run_id = result.scan_run_id
        self.runs[run_id] = _run_item(result)
        self.evidence[run_id] = _evidence_items(result)
        self.coverage_gaps[run_id] = _coverage_gap_items(result)

    def save_evaluation(self, result: EvaluationResult) -> None:
        self.findings[result.scan_run_id] = _finding_items(result)

    def get_run(self, scan_run_id: str) -> dict[str, Any] | None:
        item = self.runs.get(scan_run_id)
        return copy.deepcopy(item) if item else None

    def get_findings(self, scan_run_id: str) -> list[dict[str, Any]]:
        return copy.deepcopy(self.findings.get(scan_run_id, []))

    def get_findings_page(
        self,
        scan_run_id: str,
        *,
        limit: int,
        cursor: str | None = None,
        filters: dict[str, str] | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        criteria = validate_finding_filters(filters)
        findings = [
            finding
            for finding in self.findings.get(scan_run_id, [])
            if all(finding.get(field) == value for field, value in criteria.items())
        ]
        start = _decode_cursor(cursor)
        page = copy.deepcopy(findings[start : start + limit])
        next_index = start + len(page)
        next_cursor = _encode_cursor(next_index) if next_index < len(findings) else None
        return page, next_cursor


class DynamoDBScanStore:
    """DynamoDB adapter for the Phase 4 customer-owned table contract.

    `runs_table` must use `pk` as its partition key and `sk` as its sort key.
    `findings_table` must use the same key names and include the indexes
    described in `docs/DATA_PERSISTENCE_CONTRACT.md`.
    """

    def __init__(self, *, runs_table: Any, findings_table: Any, retention_days: int = 0) -> None:
        self._runs_table = runs_table
        self._findings_table = findings_table
        self._retention_days = retention_days

    def save_scan_result(self, result: DeterministicScanResult) -> None:
        self._runs_table.put_item(Item=with_expiry(_run_item(result), self._retention_days))
        for item in _evidence_items(result):
            self._runs_table.put_item(Item=with_expiry(item, self._retention_days))
        for item in _coverage_gap_items(result):
            self._runs_table.put_item(Item=with_expiry(item, self._retention_days))

    def save_evaluation(self, result: EvaluationResult) -> None:
        for item in _finding_items(result):
            self._findings_table.put_item(Item=with_expiry(item, self._retention_days))

    def get_findings_page(
        self,
        scan_run_id: str,
        *,
        limit: int,
        cursor: str | None = None,
        filters: dict[str, str] | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Query a single run's findings without exposing a table scan.

        Filters are applied server-side after DynamoDB reads ``limit`` items,
        so a filtered page may hold fewer items (even none) while still
        returning a cursor. Callers page until the cursor is ``None``.
        """

        from boto3.dynamodb.conditions import Attr, Key

        query: dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(_run_partition_key(scan_run_id))
            & Key("sk").begins_with("FINDING#"),
            "Limit": limit,
        }
        condition = None
        for field, value in validate_finding_filters(filters).items():
            clause = Attr(field).eq(value)
            condition = clause if condition is None else condition & clause
        if condition is not None:
            query["FilterExpression"] = condition
        if cursor:
            query["ExclusiveStartKey"] = _decode_dynamodb_cursor(cursor)
        response = self._findings_table.query(**query)
        last_evaluated_key = response.get("LastEvaluatedKey")
        return response.get("Items", []), (
            _encode_dynamodb_cursor(last_evaluated_key) if last_evaluated_key else None
        )


def with_expiry(item: dict[str, Any], retention_days: int) -> dict[str, Any]:
    """Add the DynamoDB TTL attribute; ``retention_days <= 0`` keeps records indefinitely."""

    if retention_days <= 0:
        return item
    return {**item, "expires_at": int(time.time()) + retention_days * 86400}


FINDING_FILTER_FIELDS = frozenset({"severity", "rule_id", "region", "service", "finding_state", "account_id"})


def validate_finding_filters(filters: dict[str, str] | None) -> dict[str, str]:
    """Allow only documented filter fields with short, plain values."""

    criteria: dict[str, str] = {}
    for field, value in (filters or {}).items():
        if field not in FINDING_FILTER_FIELDS:
            raise ValueError(f"Unsupported findings filter: {field}.")
        if not isinstance(value, str) or not 1 <= len(value) <= 128:
            raise ValueError(f"Invalid value for findings filter: {field}.")
        criteria[field] = value
    return criteria


def _run_item(result: DeterministicScanResult) -> dict[str, Any]:
    """Serialize the scan-result summary.

    The summary has its own sort key: `sk=RUN` is the control-plane `ScanRun`
    record owned by `DynamoDBScanRunStore`, and must never be overwritten here.
    """

    payload = result.model_dump(mode="json")
    return {
        "pk": _run_partition_key(result.scan_run_id),
        "sk": "SUMMARY",
        "entity_type": "scan_result_summary",
        "scan_run_id": result.scan_run_id,
        "status": result.status.value,
        "account_id": result.account_id,
        "schema_version": result.schema_version,
        "request": payload["request"],
        "started_at": payload["started_at"],
        "completed_at": payload["completed_at"],
        "resource_count": len(result.resources),
        "flow_count": len(result.flows),
        "coverage_gap_count": len(result.coverage_gaps),
    }


def _evidence_items(result: DeterministicScanResult) -> list[dict[str, Any]]:
    partition_key = _run_partition_key(result.scan_run_id)
    items: list[dict[str, Any]] = []
    for resource in result.resources:
        payload = resource.model_dump(mode="json")
        items.append(
            {
                "pk": partition_key,
                "sk": f"EVIDENCE#RESOURCE#{resource.evidence_id}",
                "entity_type": "resource_evidence",
                "scan_run_id": result.scan_run_id,
                **payload,
            }
        )
    for flow in result.flows:
        payload = flow.model_dump(mode="json")
        items.append(
            {
                "pk": partition_key,
                "sk": f"EVIDENCE#FLOW#{flow.evidence_id}",
                "entity_type": "flow_evidence",
                "scan_run_id": result.scan_run_id,
                **payload,
            }
        )
    return items


def _coverage_gap_items(result: DeterministicScanResult) -> list[dict[str, Any]]:
    partition_key = _run_partition_key(result.scan_run_id)
    items: list[dict[str, Any]] = []
    for gap in result.coverage_gaps:
        payload = gap.model_dump(mode="json")
        gap_id = _stable_item_id(
            result.scan_run_id,
            gap.account_id,
            gap.region,
            gap.service.value,
            gap.code,
            gap.message,
        )
        items.append(
            {
                "pk": partition_key,
                "sk": f"COVERAGE_GAP#{gap_id}",
                "entity_type": "coverage_gap",
                "scan_run_id": result.scan_run_id,
                "coverage_gap_id": gap_id,
                **payload,
            }
        )
    return items


def _finding_items(result: EvaluationResult) -> list[dict[str, Any]]:
    partition_key = _run_partition_key(result.scan_run_id)
    return [
        {
            "pk": partition_key,
            "sk": f"FINDING#{finding.finding_id}",
            "entity_type": "finding",
            "scan_run_id": result.scan_run_id,
            "rule_pack_version": result.rule_pack_version,
            "severity_created_at": f"{finding.severity}#{finding.created_at.isoformat()}",
            **finding.model_dump(mode="json"),
        }
        for finding in result.findings
    ]


def _run_partition_key(scan_run_id: str) -> str:
    return f"RUN#{scan_run_id}"


def _stable_item_id(*parts: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "|".join(parts)))


def _encode_cursor(index: int) -> str:
    return base64.urlsafe_b64encode(str(index).encode("ascii")).decode("ascii")


def _decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        decoded = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("ascii")
        index = int(decoded)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid findings cursor.") from exc
    if index < 0:
        raise ValueError("Invalid findings cursor.")
    return index


def _encode_dynamodb_cursor(key: dict[str, Any]) -> str:
    serialized = json.dumps(key, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(serialized.encode("utf-8")).decode("ascii")


def _decode_dynamodb_cursor(cursor: str) -> dict[str, Any]:
    try:
        decoded = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        key = json.loads(decoded)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid findings cursor.") from exc
    if not isinstance(key, dict) or not {"pk", "sk"}.issubset(key):
        raise ValueError("Invalid findings cursor.")
    return key
