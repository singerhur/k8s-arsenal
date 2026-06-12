"""Tests for exfiltration vectors — data integrity and search."""

import pytest
from k8s_arsenal.exfiltration.catalog import (
    EXFILTRATION_VECTORS,
    get_exfiltration_by_channel,
)


class TestExfiltrationVectors:
    """Exfiltration phase - 5 vectors expected."""

    def test_non_empty(self):
        assert len(EXFILTRATION_VECTORS) >= 4

    def test_all_vectors_have_unique_ids(self):
        ids = [v.id for v in EXFILTRATION_VECTORS]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"

    def test_all_vectors_have_required_fields(self):
        for v in EXFILTRATION_VECTORS:
            assert v.id, f"Missing id"
            assert v.name, f"Missing name for {v.id}"
            assert v.description, f"Missing description for {v.id}"

    def test_id_format(self):
        for v in EXFILTRATION_VECTORS:
            assert v.id.startswith("EXF-"), f"Bad ID format: {v.id}"

    def test_filter_by_channel_kubectl(self):
        result = get_exfiltration_by_channel("kubectl")
        assert len(result) > 0

    def test_filter_by_channel_dns(self):
        result = get_exfiltration_by_channel("dns")
        assert len(result) > 0

    def test_filter_by_channel_cloud(self):
        result = get_exfiltration_by_channel("cloud")
        assert len(result) > 0

    def test_filter_by_channel_unknown(self):
        result = get_exfiltration_by_channel("nonexistent_channel")
        assert len(result) == len(EXFILTRATION_VECTORS)
