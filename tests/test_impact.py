"""Tests for impact vectors — data integrity and search."""

import pytest
from k8s_arsenal.models import RiskLevel
from k8s_arsenal.impact.catalog import (
    IMPACT_VECTORS,
    get_impact_by_severity,
)


class TestImpactVectors:
    """Impact phase - 6 vectors expected."""

    def test_non_empty(self):
        assert len(IMPACT_VECTORS) >= 5

    def test_all_vectors_have_unique_ids(self):
        ids = [v.id for v in IMPACT_VECTORS]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"

    def test_all_vectors_have_required_fields(self):
        for v in IMPACT_VECTORS:
            assert v.id, f"Missing id"
            assert v.name, f"Missing name for {v.id}"
            assert v.description, f"Missing description for {v.id}"

    def test_id_format(self):
        for v in IMPACT_VECTORS:
            assert v.id.startswith("IMP-"), f"Bad ID format: {v.id}"

    def test_filter_by_severity_critical(self):
        result = get_impact_by_severity(RiskLevel.CRITICAL)
        assert len(result) <= len(IMPACT_VECTORS)
        for v in result:
            assert v.risk == RiskLevel.CRITICAL

    def test_filter_by_severity_high(self):
        result = get_impact_by_severity(RiskLevel.HIGH)
        assert len(result) >= 1
        risks = {RiskLevel.CRITICAL, RiskLevel.HIGH}
        for v in result:
            assert v.risk in risks

    def test_filter_by_severity_low_includes_all(self):
        result = get_impact_by_severity(RiskLevel.LOW)
        assert len(result) == len(IMPACT_VECTORS)
