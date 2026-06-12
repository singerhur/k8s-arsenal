"""Tests for credential_access vectors — data integrity and search."""

import pytest
from k8s_arsenal.credential_access.catalog import (
    CREDENTIAL_ACCESS_VECTORS,
    get_credential_access_by_target,
)


class TestCredentialAccessVectors:
    """Credential access phase - 5 vectors expected."""

    def test_non_empty(self):
        assert len(CREDENTIAL_ACCESS_VECTORS) >= 4

    def test_all_vectors_have_unique_ids(self):
        ids = [v.id for v in CREDENTIAL_ACCESS_VECTORS]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"

    def test_all_vectors_have_required_fields(self):
        for v in CREDENTIAL_ACCESS_VECTORS:
            assert v.id, f"Missing id"
            assert v.name, f"Missing name for {v.id}"
            assert v.description, f"Missing description for {v.id}"

    def test_id_format(self):
        for v in CREDENTIAL_ACCESS_VECTORS:
            assert v.id.startswith("CRD-"), f"Bad ID format: {v.id}"

    def test_filter_by_target_secret(self):
        result = get_credential_access_by_target("secret")
        assert len(result) > 0

    def test_filter_by_target_token(self):
        result = get_credential_access_by_target("token")
        assert len(result) > 0

    def test_filter_by_target_cloud(self):
        result = get_credential_access_by_target("cloud")
        assert len(result) > 0

    def test_filter_by_target_unknown(self):
        result = get_credential_access_by_target("nonexistent_target")
        assert len(result) == len(CREDENTIAL_ACCESS_VECTORS)
