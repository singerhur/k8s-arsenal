"""Tests for Alibaba Cloud ACK exploit module."""

import pytest
from k8s_arsenal.cloud.alibaba import AlibabaExploit, check_ack_risk
from k8s_arsenal.cloud.base import CloudMetadataBase, CloudCredential


def _is_alibaba_env() -> bool:
    """Check if running in Alibaba Cloud environment."""
    try:
        import requests
        resp = requests.get("http://100.100.100.200/latest/meta-data/", timeout=1)
        return resp.status_code == 200
    except Exception:
        return False


need_alibaba = pytest.mark.skipif(
    not _is_alibaba_env(),
    reason="Not running in Alibaba Cloud environment"
)


class TestAlibabaExploit:
    """Alibaba Cloud ACK exploit class tests."""

    def test_class_inherits_base(self):
        assert issubclass(AlibabaExploit, CloudMetadataBase)

    def test_class_has_required_methods(self):
        assert hasattr(AlibabaExploit, "detect")
        assert hasattr(AlibabaExploit, "get_credentials")
        assert hasattr(AlibabaExploit, "get_instance_info")
        assert callable(AlibabaExploit.detect)
        assert callable(AlibabaExploit.get_credentials)
        assert callable(AlibabaExploit.get_instance_info)

    def test_imds_base_correct(self):
        assert AlibabaExploit.IMDS_BASE == "http://100.100.100.200/latest"

    @need_alibaba
    def test_detect_in_alibaba(self):
        """detect() should return True in Alibaba Cloud environment."""
        exploit = AlibabaExploit()
        assert exploit.detect() is True

    @need_alibaba
    def test_get_credentials_in_alibaba(self):
        """get_credentials() should work in Alibaba Cloud environment."""
        exploit = AlibabaExploit()
        result = exploit.get_credentials()
        assert result is None or isinstance(result, CloudCredential)

    @need_alibaba
    def test_get_instance_info_in_alibaba(self):
        """get_instance_info() should return dict in Alibaba Cloud env."""
        exploit = AlibabaExploit()
        info = exploit.get_instance_info()
        assert isinstance(info, dict)


class TestCheckAckRisk:
    """check_ack_risk function tests."""

    def test_returns_dict(self):
        result = check_ack_risk()
        assert isinstance(result, dict)

    def test_has_required_keys(self):
        result = check_ack_risk()
        for key in ("rrsa_enabled", "role_arn", "oidc_token_mounted", "risk_level", "description"):
            assert key in result, f"Missing key: {key}"

    def test_default_values(self):
        result = check_ack_risk()
        assert result["rrsa_enabled"] is False
        assert result["oidc_token_mounted"] is False
        assert result["risk_level"] == "none"

    def test_accepts_optional_kubeconfig(self):
        result = check_ack_risk(kubeconfig=None)
        assert isinstance(result, dict)

    def test_accepts_optional_kubeconfig_path(self):
        result = check_ack_risk(kubeconfig="/nonexistent/path")
        assert isinstance(result, dict)


class TestCloudProviderIntegration:
    """Integration tests with models."""

    def test_cloud_provider_enum_has_alibaba(self):
        from k8s_arsenal.models import CloudProvider
        assert CloudProvider.ALIBABA.value == "alibaba"

    def test_alibaba_exploit_import_from_cloud_package(self):
        from k8s_arsenal.cloud import AlibabaExploit, check_ack_risk
        assert AlibabaExploit is not None
        assert callable(check_ack_risk)
