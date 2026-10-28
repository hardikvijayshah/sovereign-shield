"""Tests for the regulation registry and constraint model."""

from sovereign_shield.regulations import ALL_REGULATIONS


def test_all_regulations_loaded():
    assert len(ALL_REGULATIONS.regulations) == 7


def test_get_by_id():
    gdpr = ALL_REGULATIONS.get_by_id("gdpr")
    assert gdpr is not None
    assert gdpr.name == "EU General Data Protection Regulation"
    assert len(gdpr.constraints) == 2


def test_get_by_jurisdiction():
    eu_regs = ALL_REGULATIONS.get_by_jurisdiction("EU")
    eu_ids = {r.id for r in eu_regs}
    assert "gdpr" in eu_ids
    assert "dora" in eu_ids
    assert "nis2" in eu_ids
    assert "eu-data-act" in eu_ids


def test_gdpr_allowed_regions():
    gdpr = ALL_REGULATIONS.get_by_id("gdpr")
    constraint = gdpr.constraints[0]
    assert "eu-west-1" in constraint.allowed_regions
    assert "eu-central-1" in constraint.allowed_regions
    assert "us-east-1" not in constraint.allowed_regions


def test_gdpr_adequacy_regions():
    gdpr = ALL_REGULATIONS.get_by_id("gdpr")
    constraint = gdpr.constraints[0]
    assert constraint.allows_cross_border_with_adequacy is True
    assert "ca-central-1" in constraint.adequacy_regions
    assert "ap-northeast-1" in constraint.adequacy_regions


def test_pipl_no_cross_border():
    pipl = ALL_REGULATIONS.get_by_id("pipl")
    assert pipl is not None
    constraint = pipl.constraints[0]
    assert constraint.allows_cross_border_with_adequacy is False
    assert "cn-north-1" in constraint.allowed_regions


def test_dpdp_critical_data_stays_in_india():
    dpdp = ALL_REGULATIONS.get_by_id("dpdp")
    critical = [c for c in dpdp.constraints if "critical_personal_data" in c.data_categories][0]
    assert critical.allows_cross_border_with_adequacy is False
    assert set(critical.allowed_regions) == {"ap-south-1", "ap-south-2"}


def test_get_all_constraints():
    constraints = ALL_REGULATIONS.get_all_constraints()
    assert len(constraints) >= 7
