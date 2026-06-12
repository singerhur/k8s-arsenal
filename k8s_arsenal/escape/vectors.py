"""容器逃逸技术编目

收录已知容器逃逸技术，包括条件、利用方式、检测方法。
"""

from k8s_arsenal.models import AttackPhase, EscapeVector, RiskLevel


ESCAPE_VECTORS: list[EscapeVector] = [
    EscapeVector(
        id="ESC-001",
        name="nsenter 宿主机逃逸 (hostPID)",
        required_conditions=["hostPID", "is_container"],
        required_capabilities=["CAP_SYS_ADMIN"],
        description=(
            "利用 hostPID 和 nsenter 工具进入宿主机 namespace 获取 root shell。"
            "nsenter -t 1 -m -u -i -n -p bash"
        ),
        success_rate="high",
        detection_difficulty="hard",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.HIGH,
    ),
    EscapeVector(
        id="ESC-002",
        name="Docker Socket 挂载逃逸",
        required_conditions=["docker_sock", "is_container"],
        description=(
            "挂载的 /var/run/docker.sock 允许容器内通过 Docker API "
            "创建特权容器并逃逸至宿主机。docker run --privileged --pid=host ..."
        ),
        success_rate="high",
        detection_difficulty="medium",
        phase=AttackPhase.EXECUTION,
        risk=RiskLevel.HIGH,
    ),
    EscapeVector(
        id="ESC-003",
        name="Cgroup Release Agent 逃逸",
        cve="CVE-2022-0492",
        required_conditions=["cgroup_v1", "is_container"],
        required_capabilities=["CAP_SYS_ADMIN"],
        description=(
            "利用 cgroup v1 的 release_agent 机制，在宿主机 namespace 执行任意命令。"
            "创建子 cgroup → 写入 release_agent → 释放触发。"
        ),
        success_rate="high",
        detection_difficulty="medium",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.HIGH,
    ),
    EscapeVector(
        id="ESC-004",
        name="Privileged 模式直接逃逸",
        required_conditions=["privileged", "is_container"],
        description=(
            "privileged 容器拥有几乎所有能力，可以直接 mount 宿主机块设备 "
            "并 chroot 进入宿主机文件系统。"
        ),
        success_rate="high",
        detection_difficulty="medium",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.HIGH,
    ),
    EscapeVector(
        id="ESC-005",
        name="hostNetwork 网络嗅探",
        required_conditions=["hostNetwork", "is_container"],
        description=(
            "hostNetwork 模式容器共享宿主机网络 namespace，"
            "可嗅探宿主机流量、访问节点本地服务（Kubelet 10250 端口等）。"
        ),
        success_rate="medium",
        detection_difficulty="hard",
        phase=AttackPhase.DISCOVERY,
        risk=RiskLevel.MEDIUM,
    ),
    EscapeVector(
        id="ESC-006",
        name="/proc/sysrq-trigger 宿主机操作",
        required_conditions=["hostPID", "is_container"],
        description=(
            "通过 /proc/sysrq-trigger 向宿主机内核发送命令，"
            "可触发重启 (b)、崩溃 (c) 等。可用于 DoS 或利用证书轮换窗口。"
        ),
        success_rate="high",
        detection_difficulty="easy",
        phase=AttackPhase.IMPACT,
        risk=RiskLevel.HIGH,
    ),
    EscapeVector(
        id="ESC-007",
        name="内核模块加载逃逸",
        required_conditions=["is_container"],
        required_capabilities=["CAP_SYS_MODULE", "CAP_SYS_ADMIN"],
        description=(
            "在容器内加载内核模块 (insmod)，从内核层控制宿主机。"
            "一旦成功，所有用户态安全工具完全失效。"
        ),
        success_rate="critical",
        detection_difficulty="hard",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        risk=RiskLevel.CRITICAL,
    ),
    EscapeVector(
        id="ESC-008",
        name="Device Mapper 块设备逃逸",
        required_conditions=["privileged", "is_container"],
        description=(
            "利用 dmsetup 创建指向宿主机根文件系统的 device mapper，"
            "直接读写宿主机文件系统。可精确映射 /etc/kubernetes/pki 等敏感路径。"
        ),
        success_rate="high",
        detection_difficulty="hard",
        phase=AttackPhase.EXECUTION,
        risk=RiskLevel.HIGH,
    ),
    EscapeVector(
        id="ESC-009",
        name="PTRACE 进程注入逃逸",
        required_capabilities=["CAP_SYS_PTRACE"],
        required_conditions=["is_container", "hostPID"],
        description=(
            "利用 ptrace 向宿主机进程注入 shellcode 或劫持控制流。"
            "可用于绕过容器隔离执行宿主机代码。"
        ),
        success_rate="medium",
        detection_difficulty="hard",
        phase=AttackPhase.EXECUTION,
        risk=RiskLevel.MEDIUM,
    ),
    EscapeVector(
        id="ESC-010",
        name="CRI Socket 容器操作逃逸",
        required_conditions=["is_kubernetes", "is_container"],
        description=(
            "通过挂载的 containerd/cri-o Socket 直接操作运行时，"
            "在宿主机创建新容器或 exec 现有容器。"
        ),
        success_rate="high",
        detection_difficulty="medium",
        phase=AttackPhase.EXECUTION,
        risk=RiskLevel.HIGH,
    ),
    EscapeVector(
        id="ESC-011",
        name="Core Patterns 逃逸",
        required_conditions=["is_container"],
        required_capabilities=["CAP_SYS_ADMIN"],
        description=(
            "修改 /proc/sys/kernel/core_pattern 指向恶意脚本，"
            "当宿主机进程崩溃时触发命令执行。需要挂载宿主机文件系统。"
        ),
        success_rate="low",
        detection_difficulty="medium",
        phase=AttackPhase.EXECUTION,
        risk=RiskLevel.LOW,
    ),
    EscapeVector(
        id="ESC-012",
        name="kubelet 凭证窃取逃逸",
        required_conditions=["is_kubernetes", "is_container", "hostPID"],
        description=(
            "通过 hostPID 进入宿主机 namespace，读取 kubelet 凭证文件"
            "(kubelet-client-current.pem)，进一步访问 API Server 的 nodes/proxy 接口。"
        ),
        success_rate="high",
        detection_difficulty="hard",
        phase=AttackPhase.CREDENTIAL_ACCESS,
        risk=RiskLevel.HIGH,
    ),
]


def get_escape_vectors_by_condition(condition: str) -> list[EscapeVector]:
    """按条件筛选逃逸向量"""
    return [v for v in ESCAPE_VECTORS if condition in v.required_conditions]


def get_escape_vectors_by_capability(cap: str) -> list[EscapeVector]:
    """按能力筛选逃逸向量"""
    return [v for v in ESCAPE_VECTORS if cap in v.required_capabilities]


def get_most_dangerous_vectors() -> list[EscapeVector]:
    """获取最危险（最易利用）的逃逸向量"""
    return sorted(ESCAPE_VECTORS, key=lambda v: (
        0 if v.success_rate == "critical" else
        1 if v.success_rate == "high" else
        2 if v.success_rate == "medium" else 3
    ))
