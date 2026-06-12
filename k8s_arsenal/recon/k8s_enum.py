"""K8s 环境探测

自动检测当前运行环境，构建攻击面画像。
"""

import os
import platform
from typing import Optional

from k8s_arsenal.models import EnvironmentProfile, CloudProvider


def enumerate_environment(kubeconfig: Optional[str] = None) -> EnvironmentProfile:
    """枚举当前运行环境

    自动检测:
    - 是否运行在容器内
    - 是否在 K8s Pod 内
    - 特权模式与 hostPID/hostNetwork/hostIPC
    - 挂载的敏感路径
    - 可用的 Linux Capabilities
    - 云平台类型

    Args:
        kubeconfig: 可选 kubeconfig 路径

    Returns:
        EnvironmentProfile - 环境画像
    """
    profile = EnvironmentProfile()

    # --- 容器检测 ---
    profile.is_container = _check_is_container()

    # --- K8s 检测 ---
    profile.is_kubernetes = _check_is_kubernetes()
    if profile.is_kubernetes:
        profile.namespace = _get_current_namespace()
        profile.service_account = _get_current_service_account()

        # 挂载检测
        profile.mounted_docker_sock = _check_path("/var/run/docker.sock")
        profile.mounted_containerd_sock = _check_path("/run/containerd/containerd.sock")
        profile.mounted_crio_sock = _check_path("/var/run/crio/crio.sock")

    # --- 特权检测 ---
    profile.is_privileged = _check_privileged()

    # --- hostPID/hostNetwork/hostIPC ---
    profile.host_pid = _check_host_pid()
    profile.host_network = _check_host_network()
    profile.host_ipc = _check_host_ipc()

    # --- Capabilities ---
    profile.capabilities = _get_capabilities()

    # --- 敏感卷挂载 ---
    profile.sensitive_mounts = _check_sensitive_mounts()

    # --- 云平台检测 ---
    profile.cloud_provider = _detect_cloud_provider()

    return profile


def _check_is_container() -> bool:
    """检测是否运行在容器内

    方法:
    1. 检查 /.dockerenv 文件
    2. 检查 /proc/1/cgroup 含 docker/containerd/kubepods
    3. 检查 /proc/1/sched 中 PID 1 的进程名
    """
    # 方法 1: .dockerenv
    if os.path.exists("/.dockerenv"):
        return True

    # 方法 2: cgroup 检查
    try:
        with open("/proc/1/cgroup", "r") as f:
            content = f.read()
            if any(kw in content for kw in [
                "docker", "containerd", "kubepods",
                "libpod", "crio", "lxc"
            ]):
                return True
    except (FileNotFoundError, PermissionError):
        pass

    # 方法 3: /proc/1/sched (Linux only)
    try:
        if platform.system() == "Linux":
            with open("/proc/1/sched", "r") as f:
                first_line = f.readline()
                # 容器内 PID 1 通常不是 init/systemd
                if "init" not in first_line and "systemd" not in first_line:
                    return True
    except (FileNotFoundError, PermissionError):
        pass

    return False


def _check_is_kubernetes() -> bool:
    """检测是否在 K8s Pod 内"""
    # 检查 ServiceAccount 挂载路径
    sa_path = "/var/run/secrets/kubernetes.io/serviceaccount"
    if os.path.exists(sa_path):
        return True

    # 检查环境变量
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return True

    return False


def _get_current_namespace() -> Optional[str]:
    """获取当前命名空间"""
    ns_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    try:
        with open(ns_path, "r") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        pass
    return None


def _get_current_service_account() -> Optional[str]:
    """获取当前 ServiceAccount 名称"""
    # 从环境变量或挂载路径推断
    # 通常挂载路径下 token 文件名包含 SA 信息
    sa_dir = "/var/run/secrets/kubernetes.io/serviceaccount"
    if not os.path.exists(sa_dir):
        return None

    # 尝试读取 annotations (K8s 1.24+)
    # 更可靠的方式是通过 K8s API 查询
    try:
        import socket
        hostname = socket.gethostname()
        # hostname 在 K8s 中通常是 pod 名
        return f"<sa-of-{hostname}>"
    except Exception:
        pass
    return None


def _check_privileged() -> bool:
    """检测是否以 privileged 模式运行"""
    # 方法 1: /proc/1/status 中的 seccomp
    try:
        with open("/proc/1/status", "r") as f:
            for line in f:
                if "Seccomp:" in line:
                    if "0" in line.split(":")[1].strip():
                        # seccomp=0 且非默认 profile → 可能 privileged
                        pass
    except (FileNotFoundError, PermissionError):
        pass

    # 方法 2: 检查是否在初始 user namespace
    # privileged 容器通常在 host 的 user ns 中
    try:
        with open("/proc/self/uid_map", "r") as f:
            uid_map = f.read().rstrip()
            if uid_map == "         0          0 4294967295":
                return True
    except (FileNotFoundError, PermissionError):
        pass

    return False


def _check_host_pid() -> bool:
    """检测 hostPID"""
    # hostPID 时 /proc/1 是宿主机的 init 进程
    try:
        with open("/proc/1/cmdline", "rb") as f:
            data = f.read()
            # 宿主机 PID 1 通常是 init/systemd
            if b"systemd" in data or b"/sbin/init" in data:
                return True
    except (FileNotFoundError, PermissionError):
        pass

    # 备选：比较 /proc/1/ns/pid 与 /proc/self/ns/pid
    try:
        pid1_ns = os.readlink("/proc/1/ns/pid")
        self_ns = os.readlink("/proc/self/ns/pid")
        if pid1_ns == self_ns:
            return True
    except (FileNotFoundError, PermissionError, OSError):
        pass

    return False


def _check_host_network() -> bool:
    """检测 hostNetwork"""
    # hostNetwork 时网络 namespace 与宿主机相同
    try:
        net1_ns = os.readlink("/proc/1/ns/net")
        self_ns = os.readlink("/proc/self/ns/net")
        if self_ns == net1_ns:
            return True
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return False


def _check_host_ipc() -> bool:
    """检测 hostIPC"""
    try:
        ipc1_ns = os.readlink("/proc/1/ns/ipc")
        self_ns = os.readlink("/proc/self/ns/ipc")
        if ipc1_ns == self_ns:
            return True
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return False


def _get_capabilities() -> list[str]:
    """获取当前进程的 Linux Capabilities

    读取 /proc/self/status 中的 CapEff 掩码然后解析。
    """
    caps = []
    # 简化的能力名称映射（完整的 CapEff 位掩码解析较复杂）
    cap_names = [
        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID",
        "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN",
        "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
        "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
        "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL",
        "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN",
        "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND",
        "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
        "CAP_CHECKPOINT_RESTORE",
    ]

    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    hex_val = line.split(":")[1].strip()
                    cap_int = int(hex_val, 16)
                    for i, name in enumerate(cap_names):
                        if cap_int & (1 << i):
                            caps.append(name)
                    break
    except (FileNotFoundError, PermissionError):
        pass

    return caps


def _check_sensitive_mounts() -> list[str]:
    """检测敏感路径挂载

    检查 /proc/self/mountinfo 中是否存在对安全敏感的挂载。
    """
    sensitive_paths = [
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/var/run/crio/crio.sock",
        "/etc/kubernetes",
        "/var/lib/kubelet",
        "/var/lib/containerd",
        "/var/lib/docker",
        "/proc",
        "/sys",
        "/",
    ]

    found = []
    try:
        with open("/proc/self/mountinfo", "r") as f:
            content = f.read()
            for sp in sensitive_paths:
                if sp in content:
                    found.append(sp)
    except (FileNotFoundError, PermissionError):
        pass

    return found


def _check_path(path: str) -> bool:
    """检查路径是否存在"""
    return os.path.exists(path)


def _detect_cloud_provider() -> Optional[CloudProvider]:
    """检测云平台类型

    通过访问元数据服务端点检测:
    - AWS: 169.254.169.254 (IMDS)
    - GCP: metadata.google.internal
    - Azure: 169.254.169.254 (IMDS with Metadata header)
    - 阿里云: 100.100.100.200
    """
    # 方法 1: 通过 /sys/class/dmi/id/ 检测虚拟化平台
    try:
        vendor_files = [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/chassis_asset_tag",
        ]
        for fpath in vendor_files:
            try:
                with open(fpath, "r") as f:
                    content = f.read().lower()
                    if "amazon" in content or "ec2" in content:
                        return CloudProvider.AWS
                    if "google" in content:
                        return CloudProvider.GCP
                    if "microsoft" in content or "azure" in content:
                        return CloudProvider.AZURE
                    if "alibaba" in content or "alibabacloud" in content:
                        return CloudProvider.ALIBABA
            except (FileNotFoundError, PermissionError):
                pass
    except Exception:
        pass

    # 方法 2: HTTP 探测（可选，需要 requests）
    try:
        import requests
        # AWS IMDSv2
        try:
            r = requests.put(
                "http://169.254.169.254/latest/api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "1"},
                timeout=1
            )
            if r.status_code == 200:
                return CloudProvider.AWS
        except Exception:
            pass

        # GCP
        try:
            r = requests.get(
                "http://metadata.google.internal/computeMetadata/v1/",
                headers={"Metadata-Flavor": "Google"},
                timeout=1
            )
            if r.status_code == 200:
                return CloudProvider.GCP
        except Exception:
            pass

        # Azure
        try:
            r = requests.get(
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                headers={"Metadata": "true"},
                timeout=1
            )
            if r.status_code == 200:
                return CloudProvider.AZURE
        except Exception:
            pass

        # 阿里云
        try:
            r = requests.get("http://100.100.100.200/latest/meta-data/", timeout=1)
            if r.status_code == 200:
                return CloudProvider.ALIBABA
        except Exception:
            pass
    except ImportError:
        pass

    return None
