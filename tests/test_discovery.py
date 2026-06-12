"""Tests for discovery vectors — data integrity and search."""

import pytest
from k8s_arsenal.discovery.catalog import (
    DISCOVERY_VECTORS,
    get_discovery_by_target,
)


class TestDiscoveryVectors:
    """Discovery phase - 6 vectors expected."""

    def test_non_empty(self):
        assert len(DISCOVERY_VECTORS) >= 5

    def test_all_vectors_have_unique_ids(self):
        ids = [v.id for v in DISCOVERY_VECTORS]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"

    def test_all_vectors_have_required_fields(self):
        for v in DISCOVERY_VECTORS:
            assert v.id, f"Missing id"
            assert v.name, f"Missing name for {v.id}"
            assert v.description, f"Missing description for {v.id}"

    def test_id_format(self):
        for v in DISCOVERY_VECTORS:
            assert v.id.startswith("DIS-"), f"Bad ID format: {v.id}"

    def test_filter_by_target_api(self):
        result = get_discovery_by_target("api")
        assert len(result) > 0

    def test_filter_by_target_rbac(self):
        result = get_discovery_by_target("rbac")
        assert len(result) > 0

    def test_filter_by_target_network(self):
        result = get_discovery_by_target("network")
        assert len(result) > 0

    def test_filter_by_target_unknown(self):
        result = get_discovery_by_target("nonexistent_target")
        assert len(result) == len(DISCOVERY_VECTORS)
