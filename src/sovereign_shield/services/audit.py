"""Append-only audit records for security-relevant console and API actions."""

from __future__ import annotations

import base64
import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_MONTH_FORMAT = "%Y-%m"


class AuditOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    REJECTED = "rejected"


class AuditEvent(BaseModel):
    """One audit record. Contains identifiers only, never evidence or report content."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor_subject: str
    action: str = Field(min_length=1, max_length=64)
    target_type: str = Field(max_length=32)
    target_id: str = Field(default="", max_length=128)
    outcome: AuditOutcome
    correlation_id: str = Field(default="", max_length=128)
    details: dict[str, str] = Field(default_factory=dict)


class AuditLog(Protocol):
    """Append-only audit store."""

    def record(self, event: AuditEvent) -> None:
        """Persist one audit event."""

    def list_month(
        self, month: str, *, limit: int, cursor: str | None = None
    ) -> tuple[list[AuditEvent], str | None]:
        """Return a newest-first page of one month's events (``YYYY-MM``)."""


class AuditRecorder:
    """Best-effort recorder: an audit write failure is logged but never fails the action.

    The audited action has already happened when it is recorded, so failing the
    request would misreport an applied change as failed.
    """

    def __init__(self, log: AuditLog) -> None:
        self._log = log

    def record(self, **fields: Any) -> None:
        try:
            self._log.record(AuditEvent(**fields))
        except Exception:  # noqa: BLE001 - see class docstring
            logger.exception("AUDIT_WRITE_FAILED action=%s", fields.get("action"))


class InMemoryAuditLog:
    """Local/test audit log."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event.model_copy(deep=True))

    def list_month(
        self, month: str, *, limit: int, cursor: str | None = None
    ) -> tuple[list[AuditEvent], str | None]:
        validate_month(month)
        matching = sorted(
            (event for event in self.events if event.occurred_at.strftime(_MONTH_FORMAT) == month),
            key=lambda event: event.occurred_at,
            reverse=True,
        )
        start = int(cursor or 0)
        page = matching[start : start + limit]
        next_index = start + len(page)
        return page, (str(next_index) if next_index < len(matching) else None)


class DynamoDBAuditLog:
    """DynamoDB adapter: ``pk=AUDIT#<YYYY-MM>``, ``sk=<occurredAt>#<eventId>``.

    The API role is granted only ``PutItem`` and ``Query`` on this table, so
    records cannot be altered or deleted through the product.
    """

    def __init__(self, *, table: Any) -> None:
        self._table = table

    def record(self, event: AuditEvent) -> None:
        payload = event.model_dump(mode="json")
        self._table.put_item(
            Item={
                "pk": f"AUDIT#{event.occurred_at.strftime(_MONTH_FORMAT)}",
                "sk": f"{payload['occurred_at']}#{event.event_id}",
                **payload,
            },
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )

    def list_month(
        self, month: str, *, limit: int, cursor: str | None = None
    ) -> tuple[list[AuditEvent], str | None]:
        from boto3.dynamodb.conditions import Key

        validate_month(month)
        query: dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(f"AUDIT#{month}"),
            "ScanIndexForward": False,
            "Limit": limit,
        }
        if cursor:
            query["ExclusiveStartKey"] = _decode_cursor(cursor)
        response = self._table.query(**query)
        events = [AuditEvent.model_validate(item) for item in response.get("Items", [])]
        last_key = response.get("LastEvaluatedKey")
        return events, (_encode_cursor(last_key) if last_key else None)


def validate_month(month: str) -> None:
    try:
        parsed = datetime.strptime(month, _MONTH_FORMAT)
    except ValueError as exc:
        raise ValueError("month must use the YYYY-MM format.") from exc
    if parsed.strftime(_MONTH_FORMAT) != month:
        raise ValueError("month must use the YYYY-MM format.")


def current_month() -> str:
    return datetime.now(timezone.utc).strftime(_MONTH_FORMAT)


def audit_event_response(event: AuditEvent) -> dict[str, Any]:
    return {
        "eventId": event.event_id,
        "occurredAt": event.occurred_at.isoformat(),
        "actorSubject": event.actor_subject,
        "action": event.action,
        "targetType": event.target_type,
        "targetId": event.target_id,
        "outcome": event.outcome.value,
        "correlationId": event.correlation_id,
        "details": event.details,
    }


def _encode_cursor(key: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(key, separators=(",", ":")).encode()).decode()


def _decode_cursor(cursor: str) -> dict[str, Any]:
    try:
        key = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Invalid cursor.") from exc
    if not isinstance(key, dict) or set(key) != {"pk", "sk"}:
        raise ValueError("Invalid cursor.")
    return key
