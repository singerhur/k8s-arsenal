"""Tests for K8s environment enumeration module."""

import pytest
from unittest.mock import patch, mock_open, MagicMock
from k8s_arsenal.recon.k8s_enum import (
    _check_is_container,
    _check_is_kubernetes,
    _check_privileged,
    _get_capabilities,
    _check_sensitive_mounts,
    _check_path,
    _get_current_namespace,
    _get_current_service_account,
    enumerate_environment,
)


class TestCheckIsContainer:
    def test_dockerenv_exists(self):
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/.dockerenv"
            assert _check_is_container() is True

    def test_cgroup_contains_docker(self):
        def mock_exists(path):
            return path == "/proc/1/cgroup"
        cgroup_content = (
            "12:pids:/docker/abcdef12345\n"
            "11:devices:/docker/abcdef12345\n"
            "10:memory:/docker/abcdef12345\n"
        )
        with patch("os.path.exists", side_effect=mock_exists), \
             patch("builtins.open", mock_open(read_data=cgroup_content)):
            assert _check_is_container() is True

    def test_no_container_indicators(self):
        with patch("os.path.exists", return_value=False):
            assert _check_is_container() is False

    def test_cgroup_contains_kubepods(self):
        def mock_exists(path):
            return path == "/proc/1/cgroup"
        content = "1:name=systemd:/kubepods/burstable/pod123/"
        with patch("os.path.exists", side_effect=mock_exists), \
             patch("builtins.open", mock_open(read_data=content)):
            assert _check_is_container() is True

    def test_file_not_found(self):
        with patch("os.path.exists", return_value=False):
            assert _check_is_container() is False


class TestCheckIsKubernetes:
    def test_sa_path_exists(self):
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/var/run/secrets/kubernetes.io/serviceaccount"
            assert _check_is_kubernetes() is True

    def test_k8s_env_var(self):
        with patch("os.path.exists", return_value=False), \
             patch.dict("os.environ", {"KUBERNETES_SERVICE_HOST": "10.0.0.1"}):
            assert _check_is_kubernetes() is True

    def test_not_kubernetes(self):
        with patch("os.path.exists", return_value=False), \
             patch.dict("os.environ", {}, clear=True):
            assert _check_is_kubernetes() is False


class TestCheckPrivileged:
    def test_uid_map_wide_range(self):
        uid_content = "         0          0 4294967295\n"
        with patch("builtins.open", mock_open(read_data=uid_content)):
            assert _check_privileged() is True

    def test_uid_map_narrow_range(self):
        content = "         0       1000          1\n"
        m = MagicMock()
        m.__enter__.return_value.__iter__.return_value = iter([])
        m.__enter__.return_value.read.return_value = content
        with patch("builtins.open", return_value=m):
            assert _check_privileged() is False

    def test_no_uid_map_file(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            assert _check_privileged() is False


class TestGetCapabilities:
    def test_no_cap_file(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            assert _get_capabilities() == []

    def test_parses_capeff(self):
        # CapEff=00000000a82435fb = bits 0,1,2,3,6,7,10,12,13,21,25,27
        status_content = (
            "Name:\ttest\n"
            "CapEff:\t00000000a82435fb\n"
            "CapBnd:\t00000000a82435fb\n"
        )
        with patch("builtins.open", mock_open(read_data=status_content)):
            caps = _get_capabilities()
            assert "CAP_CHOWN" in caps
            assert "CAP_NET_ADMIN" in caps
            assert "CAP_SYS_ADMIN" in caps
            assert isinstance(caps, list)


class TestCheckSensitiveMounts:
    def test_empty_mountinfo(self):
        with patch("builtins.open", mock_open(read_data="")):
            assert _check_sensitive_mounts() == []

    def test_docker_sock_mounted(self):
        content = "/  /var/run/docker.sock docker rw,relatime 0 0\n"
        with patch("builtins.open", mock_open(read_data=content)):
            mounts = _check_sensitive_mounts()
            assert "/var/run/docker.sock" in mounts

    def test_proc_mounted(self):
        content = "proc /proc proc rw,relatime 0 0\n"
        with patch("builtins.open", mock_open(read_data=content)):
            mounts = _check_sensitive_mounts()
            assert "/proc" in mounts


class TestCheckPath:
    def test_path_exists(self):
        with patch("os.path.exists", return_value=True):
            assert _check_path("/some/path") is True

    def test_path_not_exists(self):
        with patch("os.path.exists", return_value=False):
            assert _check_path("/some/path") is False


class TestEnumerateEnvironment:
    def test_returns_environment_profile(self):
        with patch("os.path.exists", return_value=False), \
             patch.dict("os.environ", {}, clear=True), \
             patch("builtins.open", side_effect=FileNotFoundError), \
             patch("k8s_arsenal.recon.k8s_enum.platform.system", return_value="Linux"):
            profile = enumerate_environment()
            assert profile is not None
            assert hasattr(profile, "is_container")
            assert hasattr(profile, "is_kubernetes")
