"""Data models for sovereignty regulations and jurisdiction constraints."""

from __future__ import annotations

from pydantic import BaseModel


class DataResidencyConstraint(BaseModel):
    """A concrete residency rule derived from a regulation."""

    regulation_id: str
    data_categories: list[str]
    allowed_regions: list[str]
    prohibited_regions: list[str]
    requires_encryption_at_rest: bool = False
    requires_encryption_in_transit: bool = False
    allows_cross_border_with_adequacy: bool = False
    adequacy_regions: list[str] = []
    notes: str = ""


class Regulation(BaseModel):
    """A data sovereignty regulation."""

    id: str
    name: str
    jurisdiction: str
    description: str
    effective_date: str
    key_articles: list[str]
    constraints: list[DataResidencyConstraint]


class RegulationRegistry(BaseModel):
    """Collection of all known regulations."""

    regulations: list[Regulation]

    def get_by_id(self, regulation_id: str) -> Regulation | None:
        for reg in self.regulations:
            if reg.id == regulation_id:
                return reg
        return None

    def get_by_jurisdiction(self, jurisdiction: str) -> list[Regulation]:
        return [r for r in self.regulations if r.jurisdiction.lower() == jurisdiction.lower()]

    def get_all_constraints(self) -> list[DataResidencyConstraint]:
        constraints = []
        for reg in self.regulations:
            constraints.extend(reg.constraints)
        return constraints
