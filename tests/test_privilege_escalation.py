"""Tests for privilege_escalation vectors — data integrity and search."""

import pytest
from k8s_arsenal.privilege_escalation.catalog import (
    PRIVILEGE_ESCALATION_VECTORS,
    get_privilege_escalation_by_method,
)


class TestPrivilegeEscalationVectors:
    """Privilege escalation phase - 5 vectors expected."""

    def test_non_empty(self):
        assert len(PRIVILEGE_ESCALATION_VECTORS) >= 4

    def test_all_vectors_have_unique_ids(self):
        ids = [v.id for v in PRIVILEGE_ESCALATION_VECTORS]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"

    def test_all_vectors_have_required_fields(self):
        for v in PRIVILEGE_ESCALATION_VECTORS:
            assert v.id, f"Missing id"
            assert v.name, f"Missing name for {v.id}"
            assert v.description, f"Missing description for {v.id}"

    def test_id_format(self):
        for v in PRIVILEGE_ESCALATION_VECTORS:
            assert v.id.startswith("PRI-"), f"Bad ID format: {v.id}"

    def test_filter_by_method_pod(self):
        result = get_privilege_escalation_by_method("pod")
        assert len(result) > 0
        assert any("privileged" in v.description.lower() or "hostPath" in v.description.lower() for v in result)

    def test_filter_by_method_rbac(self):
        result = get_privilege_escalation_by_method("rbac")
        assert len(result) > 0

    def test_filter_by_method_token(self):
        result = get_privilege_escalation_by_method("token")
        assert len(result) > 0

    def test_filter_by_method_unknown(self):
        result = get_privilege_escalation_by_method("nonexistent_method")
        assert len(result) == len(PRIVILEGE_ESCALATION_VECTORS)
