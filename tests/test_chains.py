"""Tests for attack chain builder and export module."""

import json
import pytest
from k8s_arsenal.playbook.chains import AttackChainBuilder
from k8s_arsenal.utils.export import (
    vectors_to_json, vectors_to_markdown, vectors_to_html,
    playbook_to_json, playbook_to_markdown, export_catalog, export_playbook,
)
from k8s_arsenal.models import AttackVector, AttackPath, AttackPhase, RiskLevel


@pytest.fixture
def sample_vectors():
    return [
        AttackVector(id="V-1", name="Vector 1", phase=AttackPhase.DISCOVERY,
                     risk=RiskLevel.LOW, description="Discovery vector"),
        AttackVector(id="V-2", name="Vector 2", phase=AttackPhase.PERSISTENCE,
                     risk=RiskLevel.CRITICAL, description="Persistence vector",
                     cve="CVE-2024-1234"),
    ]


@pytest.fixture
def sample_playbooks():
    return [
        AttackPath(
            id="PB-1", name="Test Playbook",
            description="A test playbook",
            difficulty=RiskLevel.HIGH, estimated_time="1 hour",
            vectors=[
                AttackVector(id="S-1", name="Step 1", phase=AttackPhase.DISCOVERY,
                             risk=RiskLevel.LOW, description="First step"),
                AttackVector(id="S-2", name="Step 2", phase=AttackPhase.PERSISTENCE,
                             risk=RiskLevel.CRITICAL, description="Last step"),
            ],
        ),
    ]


class TestAttackChainBuilder:
    def test_init(self):
        builder = AttackChainBuilder()
        assert builder is not None

    def test_get_all_phases(self):
        builder = AttackChainBuilder()
        phases = builder.get_all_phases()
        assert isinstance(phases, dict)
        assert len(phases) > 0

    def test_get_kill_chain_coverage(self):
        builder = AttackChainBuilder()
        coverage = builder.get_kill_chain_coverage()
        assert isinstance(coverage, dict)
        # At least some phases should be covered
        covered = sum(1 for s in coverage.values() if s["covered"])
        assert covered > 0, "No phases are covered in kill chain"

    def test_build_with_known_entry(self):
        builder = AttackChainBuilder()
        chains = builder.build(entry_condition="low-privilege-sa")
        assert len(chains) > 0

    def test_build_composite_fallback(self):
        builder = AttackChainBuilder()
        chains = builder.build_composite(entry_condition="unknown-xyz")
        # Should attempt to build something
        assert isinstance(chains, list)


class TestJsonExport:
    def test_vectors_to_json(self, sample_vectors):
        result = vectors_to_json(sample_vectors)
        data = json.loads(result)
        assert data["total_vectors"] == 2
        assert len(data["vectors"]) == 2
        assert data["vectors"][0]["id"] == "V-1"
        assert data["vectors"][1]["cve"] == "CVE-2024-1234"

    def test_vectors_to_json_empty(self):
        result = vectors_to_json([])
        data = json.loads(result)
        assert data["total_vectors"] == 0

    def test_playbook_to_json(self, sample_playbooks):
        result = playbook_to_json(sample_playbooks)
        data = json.loads(result)
        assert len(data) == 1
        assert data[0]["id"] == "PB-1"
        assert data[0]["vector_count"] == 2


class TestMarkdownExport:
    def test_vectors_to_markdown(self, sample_vectors):
        result = vectors_to_markdown(sample_vectors)
        assert "Vector 1" in result
        assert "Vector 2" in result
        assert "Discovery" in result
        assert "Persistence" in result
        assert result.startswith("# ")

    def test_vectors_to_markdown_empty(self):
        result = vectors_to_markdown([])
        assert "**Total Vectors:** 0" in result

    def test_playbook_to_markdown(self, sample_playbooks):
        result = playbook_to_markdown(sample_playbooks)
        assert "PB-1" in result
        assert "Test Playbook" in result
        assert "Step 1" in result
        assert "Step 2" in result


class TestHtmlExport:
    def test_vectors_to_html(self, sample_vectors):
        result = vectors_to_html(sample_vectors)
        assert "<!DOCTYPE html>" in result
        assert "Vector 1" in result
        assert "Vector 2" in result
        assert "CVE-2024-1234" in result

    def test_vectors_to_html_standalone(self, sample_vectors):
        result = vectors_to_html(sample_vectors, standalone=True)
        assert "<!DOCTYPE html>" in result
        assert "</html>" in result

    def test_vectors_to_html_not_standalone(self, sample_vectors):
        result = vectors_to_html(sample_vectors, standalone=False)
        assert "<!DOCTYPE html>" not in result


class TestExportToFile:
    def test_export_catalog_json(self, sample_vectors, tmp_path):
        out = tmp_path / "catalog.json"
        export_catalog(sample_vectors, str(out), fmt="json")
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["total_vectors"] == 2

    def test_export_catalog_md(self, sample_vectors, tmp_path):
        out = tmp_path / "catalog.md"
        export_catalog(sample_vectors, str(out), fmt="md")
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "Vector 1" in content

    def test_export_catalog_html(self, sample_vectors, tmp_path):
        out = tmp_path / "catalog.html"
        export_catalog(sample_vectors, str(out), fmt="html")
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_export_catalog_invalid_format(self, sample_vectors, tmp_path):
        out = tmp_path / "catalog.xyz"
        with pytest.raises(ValueError, match="Unsupported format"):
            export_catalog(sample_vectors, str(out), fmt="xyz")

    def test_export_playbook_json(self, sample_playbooks, tmp_path):
        out = tmp_path / "playbook.json"
        export_playbook(sample_playbooks, str(out), fmt="json")
        assert out.exists()

    def test_export_playbook_invalid_format(self, sample_playbooks, tmp_path):
        out = tmp_path / "playbook.xyz"
        with pytest.raises(ValueError, match="Unsupported format"):
            export_playbook(sample_playbooks, str(out), fmt="xyz")
