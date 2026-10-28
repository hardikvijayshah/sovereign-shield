"""Data models for AWS resource scanning results."""

from __future__ import annotations

from pydantic import BaseModel


class CrossBorderFlow(BaseModel):
    """A detected cross-border data movement."""

    service: str
    resource_arn: str
    resource_name: str
    source_region: str
    destination_regions: list[str]
    flow_type: str  # replication, edge_cache, backup, stream, peering
    encryption_enabled: bool = False
    account_id: str = ""
    details: dict = {}


class ResourceInventory(BaseModel):
    """Inventory of a single AWS resource with data residency implications."""

    service: str
    resource_arn: str
    resource_name: str
    region: str
    account_id: str
    resource_type: str
    encryption_at_rest: bool = False
    encryption_in_transit: bool = False
    tags: dict[str, str] = {}
    details: dict = {}


class ScanResult(BaseModel):
    """Complete result from scanning an AWS environment."""

    account_id: str
    regions_scanned: list[str]
    resources: list[ResourceInventory] = []
    cross_border_flows: list[CrossBorderFlow] = []
    errors: list[str] = []
