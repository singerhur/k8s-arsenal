"""Tests for attack vector catalogs — data integrity and search."""

import pytest
from k8s_arsenal.escape.vectors import ESCAPE_VECTORS
from k8s_arsenal.persistence.catalog import PERSISTENCE_VECTORS
from k8s_arsenal.lateral.movement import LATERAL_VECTORS
from k8s_arsenal.network.attacks import NETWORK_VECTORS
from k8s_arsenal.supply_chain.catalog import SUPPLY_CHAIN_VECTORS, get_supply_chain_by_type
from k8s_arsenal.evasion.catalog import EVASION_VECTORS, get_evasion_by_target
from k8s_arsenal.playbook.templates import CHAIN_TEMPLATES, get_playbook_by_entry


class TestEscapeVectors:
    def test_all_vectors_have_unique_ids(self):
        ids = [v.id for v in ESCAPE_VECTORS]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"

    def test_all_vectors_have_required_fields(self):
        for v in ESCAPE_VECTORS:
            assert v.id and len(v.id) > 0
            assert v.name and len(v.name) > 0
            assert v.description and len(v.description) > 0

    def test_filter_by_name(self):
        result = [v for v in ESCAPE_VECTORS if "socket" in v.name.lower() or "docker" in v.name.lower()]
        assert len(result) > 0

    def test_filter_no_match(self):
        result = [v for v in ESCAPE_VECTORS if "nonexistent_technique_xyz" in v.name.lower()]
        assert result == []


class TestPersistenceVectors:
    def test_unique_ids(self):
        ids = [v.id for v in PERSISTENCE_VECTORS]
        assert len(ids) == len(set(ids))

    def test_all_valid_phase(self):
        for v in PERSISTENCE_VECTORS:
            assert v.phase is not None


class TestLateralVectors:
    def test_unique_ids(self):
        ids = [v.id for v in LATERAL_VECTORS]
        assert len(ids) == len(set(ids))


class TestNetworkVectors:
    def test_unique_ids(self):
        ids = [v.id for v in NETWORK_VECTORS]
        assert len(ids) == len(set(ids))


class TestSupplyChainVectors:
    def test_unique_ids(self):
        ids = [v.id for v in SUPPLY_CHAIN_VECTORS]
        assert len(ids) == len(set(ids))

    def test_get_by_type_helm(self):
        result = get_supply_chain_by_type("helm")
        assert len(result) > 0
        for v in result:
            assert "helm" in v.name.lower() or "helm" in v.description.lower() or "chart" in v.name.lower()

    def test_get_by_type_gitops(self):
        result = get_supply_chain_by_type("gitops")
        assert len(result) > 0

    def test_get_by_type_invalid(self):
        result = get_supply_chain_by_type("nonexistent")
        # Should return all vectors
        assert len(result) == len(SUPPLY_CHAIN_VECTORS)


class TestEvasionVectors:
    def test_unique_ids(self):
        ids = [v.id for v in EVASION_VECTORS]
        assert len(ids) == len(set(ids))

    def test_get_by_target_audit(self):
        result = get_evasion_by_target("audit")
        assert len(result) > 0
        for v in result:
            desc = (v.name + v.description).lower()
            assert any(kw in desc for kw in ["audit", "审计", "日志"])

    def test_get_by_target_falco(self):
        result = get_evasion_by_target("falco")
        assert len(result) > 0


class TestPlaybookTemplates:
    def test_all_templates_have_unique_ids(self):
        ids = [p.id for p in CHAIN_TEMPLATES]
        assert len(ids) == len(set(ids))

    def test_all_templates_have_vectors(self):
        for p in CHAIN_TEMPLATES:
            assert len(p.vectors) > 0, f"Template {p.id} has no vectors"

    def test_get_by_entry_exact(self):
        result = get_playbook_by_entry("low-privilege-sa")
        assert len(result) == 1
        assert result[0].id == "PB-A"

    def test_get_by_entry_eks(self):
        result = get_playbook_by_entry("eks-irsa")
        assert len(result) == 1
        assert result[0].id == "PB-C"

    def test_get_by_entry_dns(self):
        result = get_playbook_by_entry("dns-control")
        assert len(result) == 1
        assert result[0].id == "PB-B"

    def test_get_by_entry_invalid(self):
        result = get_playbook_by_entry("completely-invalid-entry-point")
        assert len(result) == len(CHAIN_TEMPLATES)  # Returns all
