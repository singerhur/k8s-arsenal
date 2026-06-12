"""集群内自检脚本 — 从 Pod 内部评估攻击面

运行于 K8s Pod 内，全面检查：
- ServiceAccount 权限（通过 SelfSubjectAccessReview）
- 容器安全上下文（capabilities, privileged, seccomp, AppArmor）
- 挂载卷（service account token, hostPath, configmap, secret）
- 网络可访问性（API Server, kubelet, etcd, cloud metadata）
- 环境变量中的敏感信息
- 运行时风险评分

用法:
    k8s-arsenal self-check          # CLI 入口
    python -m k8s_arsenal.utils.self_check  # 直接运行
"""

import os
import sys
import json
import socket
import platform
from dataclasses import dataclass, field
from typing import Optional

from k8s_arsenal.models import RiskLevel


@dataclass
class SelfCheckResult:
    """自检单项结果"""
    category: str
    name: str
    status: str  # "pass", "warn", "fail", "info"
    risk: RiskLevel
    detail: str
    remediation: str = ""


@dataclass
class SelfCheckReport:
    """完整自检报告"""
    timestamp: str = ""
    node_name: str = ""
    namespace: str = ""
    pod_name: str = ""
    service_account: str = ""
    container_image: str = ""
    results: list[SelfCheckResult] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        """计算风险评分 (0-200)

        FAIL = 权重全值，WARN = 权重半值。
        取消 100 上限，让不同安全等级的 Pod 有明显区分度。
        """
        weights = {
            RiskLevel.CRITICAL: 25,
            RiskLevel.HIGH: 15,
            RiskLevel.MEDIUM: 5,
            RiskLevel.LOW: 1,
        }
        score = 0
        for r in self.results:
            if r.status == "fail":
                score += weights.get(r.risk, 1)
            elif r.status == "warn":
                score += weights.get(r.risk, 1) // 2
        return min(score, 200)


class PodSelfChecker:
    """Pod 内自治攻击面扫描器"""

    def __init__(self, k8s_client=None):
        self._client = k8s_client
        self._results: list[SelfCheckResult] = []
        # 以下字段由 _check_identity() 填充，供 _build_report() 复用
        self._identity_ns: str = ""
        self._identity_sa: str = ""
        self._identity_node: str = ""
        self._identity_pod: str = ""

    def check(self, use_k8s_api: bool = True) -> SelfCheckReport:
        """执行全量检查"""
        self._results.clear()

        # 基本信息
        self._check_identity()
        self._check_capabilities()
        self._check_seccomp_apparmor()
        self._check_mounts()
        self._check_environment()
        self._check_network()
        self._check_runtime()
        self._check_filesystem()

        if use_k8s_api:
            try:
                self._check_rbac()
            except Exception:
                pass

        return self._build_report()

    def _record(self, category: str, name: str, status: str,
                risk: RiskLevel, detail: str, remediation: str = ""):
        self._results.append(SelfCheckResult(
            category=category, name=name, status=status,
            risk=risk, detail=detail, remediation=remediation,
        ))

    def _check_identity(self):
        """检查 Pod 身份"""
        # 优先读环境变量（Downward API），无则从 SA token 文件回退
        ns = os.environ.get("KUBERNETES_NAMESPACE", "")
        if not ns:
            try:
                ns = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r").read().strip()
            except Exception:
                ns = "unknown"

        sa = os.environ.get("KUBERNETES_SERVICE_ACCOUNT", "")
        if not sa:
            try:
                # 从挂载 token 解析 client ID（service-account-name）
                token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
                if os.path.exists(token_path):
                    import base64
                    parts = open(token_path, "r").read().strip().split(".")
                    if len(parts) == 3:
                        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
                        sa = payload.get("sub", "").split(":")[-1]
            except Exception:
                sa = "unknown"
        sa = sa or "unknown"

        node = os.environ.get("KUBERNETES_NODE_NAME", "")
        if not node:
            try:
                node = open("/proc/self/cgroup", "r").read().split("\n")[0].split("/")[-1] or ""
            except Exception:
                node = ""
        node = node or "unknown"

        pod = os.environ.get("HOSTNAME", "unknown")

        # 保存解析后的身份值供 _build_report() 复用
        self._identity_ns = ns
        self._identity_sa = sa
        self._identity_node = node
        self._identity_pod = pod

        self._record("identity", "ServiceAccount",
            "info", RiskLevel.LOW,
            f"SA: {sa}, Namespace: {ns}, Node: {node}, Pod: {pod}")

        # 检查是否在 default 命名空间（通常权限较大）
        if ns == "default":
            self._record("identity", "Default Namespace",
                "warn", RiskLevel.MEDIUM,
                "Pod in 'default' namespace — usually less restricted",
                "Move to dedicated namespace with NetworkPolicy")

        # 检查 kube-system 等敏感命名空间
        if ns in ("kube-system", "kube-public", "istio-system"):
            self._record("identity", "Sensitive Namespace",
                "warn", RiskLevel.HIGH,
                f"Pod in '{ns}' — cluster-critical namespace",
                "Ensure strict RBAC and admission controls")

    def _check_capabilities(self):
        """检查 Linux Capabilities"""
        try:
            cap_file = "/proc/self/status"
            if os.path.exists(cap_file):
                with open(cap_file, "r") as f:
                    for line in f:
                        if line.startswith("Cap"):
                            self._record("capabilities", line.strip(),
                                "info", RiskLevel.LOW,
                                "Raw capability bitmap — verify with capsh --decode=")

            # 检查常见危险能力
            dangerous = {
                "SYS_ADMIN": "Can mount filesystems, load kernel modules",
                "SYS_PTRACE": "Can ptrace any process, escape sandbox",
                "SYS_MODULE": "Can load/unload kernel modules",
                "SYS_RAWIO": "Can direct hardware I/O access, port I/O",
                "SYS_CHROOT": "Can call chroot() for container escape",
                "SYS_BOOT": "Can reboot and reboot into alternate kernel",
                "SYS_RESOURCE": "Can modify resource limits above max",
                "SYS_NICE": "Can change process priority and set SCHED_FIFO",
                "NET_ADMIN": "Can modify network stack, iptables",
                "NET_RAW": "Can create raw sockets",
                "DAC_READ_SEARCH": "Can bypass directory read/search permissions",
                "DAC_OVERRIDE": "Can bypass file read/write permission checks",
                "SETUID": "Can manipulate process UIDs for privilege escalation",
                "SETGID": "Can manipulate process GIDs for privilege escalation",
                "MAC_ADMIN": "Can change SMACK/LSM MAC configuration",
                "MAC_OVERRIDE": "Can bypass SMACK/LSM MAC checks",
                "SYSLOG": "Can view kernel logs containing secrets",
                "BPF": "Can load eBPF programs for kernel-level monitoring/escape",
                "PERFMON": "Can monitor system performance tracepoints",
                "CHECKPOINT_RESTORE": "Can checkpoint/restore processes for container escape",
                "AUDIT_CONTROL": "Can disable audit logging for evasion",
                "LINUX_IMMUTABLE": "Can set FS_IMMUTABLE_FL for persistence",
            }

            cap_eff = None
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("CapEff:"):
                        cap_eff = int(line.split(":")[1].strip(), 16)
                        break

            if cap_eff is not None:
                import ctypes
                # 完整能力映射（Linux <5.13, 不含已废弃能力）
                cap_names = {
                    0:   "CHOWN",
                    1:   "DAC_OVERRIDE",
                    2:   "DAC_READ_SEARCH",
                    3:   "FOWNER",
                    4:   "FSETID",
                    5:   "KILL",
                    6:   "SETGID",
                    7:   "SETUID",
                    8:   "SETPCAP",
                    9:   "LINUX_IMMUTABLE",
                    10:  "NET_BIND_SERVICE",
                    11:  "NET_BROADCAST",
                    12:  "NET_ADMIN",
                    13:  "NET_RAW",
                    14:  "IPC_LOCK",
                    15:  "IPC_OWNER",
                    16:  "SYS_MODULE",
                    17:  "SYS_RAWIO",
                    18:  "SYS_CHROOT",
                    19:  "SYS_PTRACE",
                    20:  "SYS_PACCT",
                    21:  "SYS_ADMIN",
                    22:  "SYS_BOOT",
                    23:  "SYS_NICE",
                    24:  "SYS_RESOURCE",
                    25:  "SYS_TIME",
                    26:  "SYS_TTY_CONFIG",
                    27:  "MKNOD",
                    28:  "LEASE",
                    29:  "AUDIT_WRITE",
                    30:  "AUDIT_CONTROL",
                    31:  "SETFCAP",
                    32:  "MAC_OVERRIDE",
                    33:  "MAC_ADMIN",
                    34:  "SYSLOG",
                    35:  "WAKE_ALARM",
                    36:  "BLOCK_SUSPEND",
                    37:  "AUDIT_READ",
                    38:  "PERFMON",
                    39:  "BPF",
                    40:  "CHECKPOINT_RESTORE",
                }
                for bit, name in cap_names.items():
                    if cap_eff & (1 << bit):
                        self._record("capabilities", f"CAP_{name}",
                            "warn" if name in dangerous else "info",
                            RiskLevel.HIGH if name in ("SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE") else RiskLevel.MEDIUM,
                            dangerous.get(name, f"CAP_{name} enabled"),
                            "Drop unused capabilities")

        except Exception as e:
            self._record("capabilities", "Capability Check Failed",
                "warn", RiskLevel.LOW, str(e))

    def _check_seccomp_apparmor(self):
        """检查安全 Profile"""
        # Seccomp
        seccomp_path = "/proc/self/status"
        try:
            with open(seccomp_path, "r") as f:
                content = f.read()
                if "Seccomp:" in content:
                    seccomp_line = [l for l in content.split("\n") if l.startswith("Seccomp:")]
                    mode = seccomp_line[0].split(":")[1].strip() if seccomp_line else "unknown"
                    if mode == "2":
                        self._record("seccomp", "Seccomp Filter",
                            "pass", RiskLevel.LOW,
                            "Seccomp filter mode active (filtering)")
                    elif mode == "1":
                        self._record("seccomp", "Seccomp Strict",
                            "info", RiskLevel.LOW,
                            "Seccomp strict mode (read/write/exit/sigreturn only)")
                    else:
                        self._record("seccomp", "No Seccomp",
                            "fail", RiskLevel.HIGH,
                            "No seccomp profile — all syscalls allowed",
                            "Apply RuntimeDefault seccomp profile")
        except Exception:
            pass

        # AppArmor
        try:
            with open("/proc/self/attr/current", "r") as f:
                aa = f.read().strip()
                if aa and aa != "unconfined":
                    self._record("apparmor", "AppArmor Profile",
                        "pass", RiskLevel.LOW, f"Active: {aa}")
                else:
                    self._record("apparmor", "No AppArmor",
                        "warn", RiskLevel.MEDIUM,
                        "AppArmor not active — consider using constrained profiles")
        except Exception:
            pass

    def _check_mounts(self):
        """检查挂载卷"""
        try:
            with open("/proc/self/mounts", "r") as f:
                mounts = f.read()

            # SA Token
            if "/var/run/secrets/kubernetes.io/serviceaccount" in mounts:
                self._record("mounts", "SA Token Mount",
                    "warn", RiskLevel.MEDIUM,
                    "ServiceAccount token mounted (default behavior)",
                    "Consider automountServiceAccountToken: false if not needed")

            # hostPath risks
            hostpath_risks = {
                "/var/run/docker.sock": ("Docker Socket", RiskLevel.CRITICAL,
                    "Docker socket mounted — full container escape possible",
                    "Never mount docker.sock unless absolutely necessary"),
                "/run/containerd/containerd.sock": ("Containerd Socket", RiskLevel.CRITICAL,
                    "Containerd socket mounted — full container escape",
                    "Avoid mounting runtime sockets"),
                "/var/log": ("Host Logs", RiskLevel.HIGH,
                    "Host /var/log mounted — can create symlinks to steal credentials",
                    "Mount with readOnly: true, avoid recursive mount"),
                "/etc/kubernetes": ("K8s PKI", RiskLevel.CRITICAL,
                    "Kubernetes PKI directory mounted — cluster compromise",
                    "Never mount K8s CA directories"),
                "/var/lib/kubelet": ("Kubelet Data", RiskLevel.CRITICAL,
                    "Kubelet data directory mounted — pod escape, credential theft",
                    "Never mount kubelet data directory"),
                "/root": ("Host Root", RiskLevel.CRITICAL,
                    "Host root home directory mounted",
                    "Avoid mounting sensitive host directories"),
            }

            # 容器自身的虚拟文件系统，不应被误判为 hostPath
            _container_fs_types = {"proc", "sysfs", "cgroup", "cgroup2",
                                   "devpts", "devtmpfs", "tmpfs", "mqueue",
                                   "configfs", "bpf", "debugfs", "tracefs",
                                   "fusectl", "securityfs", "pstore"}

            # 逐行解析 /proc/self/mounts，精确匹配挂载点
            for line in mounts.split("\n"):
                parts = line.split()
                if len(parts) < 3:
                    continue
                mount_point = parts[1]
                fs_type = parts[2]
                # 跳过容器自身的虚拟文件系统
                if fs_type in _container_fs_types:
                    continue
                if mount_point in hostpath_risks:
                    name, risk, detail, remediation = hostpath_risks[mount_point]
                    self._record("mounts", name, "fail", risk, detail, remediation)

            # RW hostPaths — parse mount point from field [1], skip device mounts
            rw_count = 0
            for line in mounts.split("\n"):
                parts = line.split()
                if len(parts) < 4:
                    continue
                mount_point = parts[1]
                options = parts[3]
                # Only count RW non-device mounts (check mount_point, not device field)
                if mount_point.startswith("/") and not mount_point.startswith("/dev/") and "rw," in options:
                    rw_count += 1
            if rw_count > 5:
                self._record("mounts", "Many RW Mounts",
                    "warn", RiskLevel.MEDIUM,
                    f"{rw_count} read-write mounts found",
                    "Reduce to minimum necessary, use readOnly: true")

        except Exception as e:
            self._record("mounts", "Mount Check Failed",
                "warn", RiskLevel.LOW, str(e))

    def _check_environment(self):
        """检查环境变量中的敏感信息"""
        sensitive_keywords = [
            "SECRET", "PASSWORD", "PASSWD", "TOKEN", "KEY",
            "CREDENTIAL", "AUTH", "CERT", "PRIVATE",
            "AWS_ACCESS", "AWS_SECRET", "AZURE_CLIENT_SECRET",
            "GCP_SA_KEY", "KUBECONFIG",
        ]
        found = []
        for key, value in os.environ.items():
            upper_key = key.upper()
            for kw in sensitive_keywords:
                if kw in upper_key:
                    found.append(key)

        if found:
            self._record("environment", "Sensitive Env Vars",
                "warn", RiskLevel.HIGH,
                f"Potentially sensitive env vars: {', '.join(found)}",
                "Use Kubernetes Secrets mounted as files instead of env vars")

        # 检查云环境变量
        cloud_indicators = []
        for key in os.environ:
            upper = key.upper()
            if "AWS_" in upper or "ECS_" in upper or "EKS_" in upper:
                cloud_indicators.append("AWS")
                break
        if "GCP_" in os.environ.get("HOME", "") or os.path.exists("/var/run/secrets/gcp"):
            cloud_indicators.append("GCP")
        for key in os.environ:
            if "AZURE_" in key.upper():
                cloud_indicators.append("Azure")
                break

        if cloud_indicators:
            self._record("environment", "Cloud Environment",
                "info", RiskLevel.LOW,
                f"Detected: {', '.join(set(cloud_indicators))}")

    def _check_network(self):
        """检查网络可访问性"""
        targets = [
            ("K8s API", os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc"),
             os.environ.get("KUBERNETES_SERVICE_PORT", "443")),
            ("Kubelet", os.environ.get("KUBERNETES_NODE_NAME", "localhost"), "10250"),
            ("Etcd", "localhost", "2379"),
            ("GCP Metadata", "metadata.google.internal", "80"),
            ("AWS Metadata", "169.254.169.254", "80"),
            ("Azure Metadata", "169.254.169.254", "80"),
        ]

        for name, host, port in targets:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((host, int(port)))
                sock.close()
                if result == 0:
                    if name in ("GCP Metadata", "AWS Metadata", "Azure Metadata"):
                        self._record("network", f"{name} Accessible",
                            "fail", RiskLevel.CRITICAL,
                            f"Cloud metadata {host}:{port} accessible — credential theft risk",
                            "Block metadata access via NetworkPolicy or iptables")
                    elif name == "Etcd":
                        self._record("network", "Etcd Accessible",
                            "fail", RiskLevel.CRITICAL,
                            f"etcd {host}:{port} accessible — full cluster compromise",
                            "Restrict etcd access with firewall rules")
                    elif name == "Kubelet":
                        self._record("network", "Kubelet Accessible",
                            "warn", RiskLevel.HIGH,
                            f"Kubelet API {host}:{port} accessible",
                            "Restrict kubelet access NetworkPolicy")
            except Exception:
                pass

    def _check_runtime(self):
        """检查运行时环境"""
        # 是否 root 用户
        try:
            uid = os.getuid()
            if uid == 0:
                self._record("runtime", "Running as Root",
                    "fail", RiskLevel.HIGH,
                    f"Container running as UID {uid} (root)",
                    "Set securityContext.runAsNonRoot: true, use non-root user")
        except Exception:
            pass

        # PID namespace
        try:
            pids = [d for d in os.listdir("/proc") if d.isdigit()]
            if len(pids) > 10:
                self._record("runtime", "Shared PID Namespace",
                    "warn", RiskLevel.MEDIUM,
                    f"Can see {len(pids)} processes — shared PID namespace",
                    "Set hostPID: false, enable shareProcessNamespace only if needed")
        except Exception:
            pass

        # 检查是否 privileged
        try:
            if os.path.exists("/dev") and os.path.exists("/proc/1/cgroup"):
                with open("/proc/1/cgroup", "r") as f:
                    cgroup = f.read()
                # privileged 容器通常挂载全量 /dev
                dev_count = len([d for d in os.listdir("/dev") if not d.startswith(".")])
                if dev_count > 50:
                    self._record("runtime", "Excessive /dev Access",
                        "warn", RiskLevel.HIGH,
                        f"{dev_count} devices visible — likely privileged container",
                        "Set privileged: false, use device-specific mounts")
        except Exception:
            pass

    def _check_filesystem(self):
        """检查文件系统中的凭证"""
        searches = [
            # SSH Keys
            ("/root/.ssh/id_rsa", "SSH Private Key", RiskLevel.CRITICAL),
            ("/home/*/.ssh/id_rsa", "SSH Private Key (home)", RiskLevel.CRITICAL),
            # K8s credentials
            ("/var/run/secrets/kubernetes.io/serviceaccount/token", "SA Token", RiskLevel.MEDIUM),
            ("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "K8s CA Cert", RiskLevel.LOW),
            # Cloud credentials
            ("/var/run/secrets/gcp", "GCP SA Key", RiskLevel.CRITICAL),
            # Git credentials
            ("/root/.git-credentials", "Git Credentials", RiskLevel.HIGH),
            ("/root/.netrc", ".netrc Credentials", RiskLevel.MEDIUM),
            # Docker config
            ("/root/.docker/config.json", "Docker Config", RiskLevel.MEDIUM),
            # AWS
            ("/root/.aws/credentials", "AWS Credentials", RiskLevel.CRITICAL),
            # Kubeconfig (not from SA)
            ("/root/.kube/config", "User Kubeconfig", RiskLevel.CRITICAL),
            ("/home/*/.kube/config", "User Kubeconfig (home)", RiskLevel.CRITICAL),
        ]

        import glob
        for path, name, risk in searches:
            if "*" in path:
                matches = glob.glob(path)
                for m in matches:
                    self._record("filesystem", name, "fail", risk,
                        f"Found: {m}",
                        "Remove credentials from container image")
            elif os.path.exists(path):
                self._record("filesystem", name,
                    "fail" if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH) else "warn",
                    risk,
                    f"Found: {path}",
                    "Remove credentials from container image")

    def _check_rbac(self):
        """通过 SelfSubjectAccessReview 检查 RBAC 权限"""
        try:
            from kubernetes import client, config
            config.load_incluster_config()
            auth_v1 = client.AuthorizationV1Api()

            dangerous_checks = [
                # 资源级
                ("secrets", "", "list", "List All Secrets"),
                ("secrets", "", "get", "Get Secrets"),
                ("pods", "", "list", "List All Pods"),
                ("pods", "", "create", "Create Pods"),
                ("pods", "", "delete", "Delete Pods"),
                ("pods", "", "exec", "Exec Into Pods"),
                ("pods", "", "ephemeralcontainers", "Ephemeral Container Injection"),
                ("deployments", "", "create", "Create Deployments"),
                ("deployments", "", "patch", "Patch Deployments"),
                ("services", "", "create", "Create Services"),
                ("nodes", "", "list", "List Nodes"),
                ("clusterroles", "", "bind", "Bind ClusterRoles"),
                ("clusterrolebindings", "", "create", "Create ClusterRoleBindings"),
                ("rolebindings", "", "create", "Create RoleBindings"),
                ("serviceaccounts", "", "create", "Create ServiceAccounts"),
                ("tokenreviews", "", "create", "Create TokenReviews"),
                ("certificatesigningrequests", "", "create", "Create CSRs"),
                ("validatingwebhookconfigurations", "", "create", "Create ValidatingWebhook"),
                ("mutatingwebhookconfigurations", "", "create", "Create MutatingWebhook"),
                # 子资源
                ("pods/log", "", "get", "Read Pod Logs"),
                ("serviceaccounts/token", "", "create", "Create SA Tokens"),
            ]

            for resource, subresource, verb, desc in dangerous_checks:
                review = auth_v1.create_self_subject_access_review(
                    client.V1SelfSubjectAccessReview(
                        spec=client.V1SelfSubjectAccessReviewSpec(
                            resource_attributes=client.V1ResourceAttributes(
                                verb=verb,
                                resource=resource.split("/")[0],
                                subresource=resource.split("/")[1] if "/" in resource else None,
                            )
                        )
                    )
                )
                if review.status.allowed:
                    severity = RiskLevel.CRITICAL if verb in ("create", "bind", "exec") else RiskLevel.HIGH
                    self._record("rbac", desc, "fail", severity,
                        f"SA can {verb} {resource}",
                        "Restrict RBAC to minimum necessary permissions")

        except ImportError:
            self._record("rbac", "k8s client unavailable",
                "info", RiskLevel.LOW, "kubernetes client not installed")
        except Exception as e:
            self._record("rbac", "RBAC Check Failed",
                "warn", RiskLevel.LOW, str(e))

    def _build_report(self) -> SelfCheckReport:
        from datetime import datetime
        return SelfCheckReport(
            timestamp=datetime.now().isoformat(),
            node_name=self._identity_node or os.environ.get("KUBERNETES_NODE_NAME", ""),
            namespace=self._identity_ns or os.environ.get("KUBERNETES_NAMESPACE", ""),
            pod_name=self._identity_pod or os.environ.get("HOSTNAME", ""),
            service_account=self._identity_sa or os.environ.get("KUBERNETES_SERVICE_ACCOUNT", ""),
            container_image=os.environ.get("IMAGE", ""),
            results=self._results,
        )


def run_self_check() -> SelfCheckReport:
    """入口：运行完整自检并返回报告"""
    checker = PodSelfChecker()
    return checker.check()


def print_self_check(report: Optional[SelfCheckReport] = None) -> SelfCheckReport:
    """CLI 友好输出"""
    if report is None:
        report = run_self_check()

    status_icons = {"pass": "\u2705", "warn": "\u26a0\ufe0f", "fail": "\u274c", "info": "\u2139\ufe0f"}

    print(f"\n{'='*60}")
    print(f"  K8s Arsenal — Pod Self-Check Report")
    print(f"{'='*60}")
    print(f"  Namespace:     {report.namespace}")
    print(f"  Pod:           {report.pod_name}")
    print(f"  ServiceAccount:{report.service_account}")
    print(f"  Node:          {report.node_name}")
    print(f"  Risk Score:    {report.risk_score}/200")
    print(f"{'='*60}\n")

    by_category: dict[str, list[SelfCheckResult]] = {}
    for r in report.results:
        by_category.setdefault(r.category, []).append(r)

    for cat, results in by_category.items():
        print(f"\n  [{cat.upper()}]")
        for r in results:
            icon = status_icons.get(r.status, "?")
            print(f"    {icon} {r.name}: {r.detail}")
            if r.remediation:
                print(f"       \u2192 {r.remediation}")

    print(f"\n{'='*60}")
    fail_count = sum(1 for r in report.results if r.status == "fail")
    warn_count = sum(1 for r in report.results if r.status == "warn")
    print(f"  {fail_count} FAIL  {warn_count} WARN  Score: {report.risk_score}/200")
    print(f"{'='*60}\n")

    return report
