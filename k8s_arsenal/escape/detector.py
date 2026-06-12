"""容器逃逸条件检测

基于当前环境画像，匹配已知逃逸技术的必要条件。
"""

from typing import Any

from k8s_arsenal.models import EnvironmentProfile, EscapeVector
from k8s_arsenal.escape.vectors import ESCAPE_VECTORS


def detect_escape_vectors(profile: EnvironmentProfile) -> list[EscapeVector]:
    """检测当前环境可能利用的逃逸向量

    遍历已知逃逸技术编目，逐一匹配必要条件。

    Args:
        profile: 环境画像

    Returns:
        匹配的逃逸向量列表
    """
    matched = []

    for vector in ESCAPE_VECTORS:
        if _check_vector_conditions(vector, profile):
            matched.append(vector)

    return matched


def _check_vector_conditions(vector: EscapeVector, profile: EnvironmentProfile) -> bool:
    """检查逃逸向量的必要条件是否满足"""

    # 检查 capabilities
    for cap in vector.required_capabilities:
        if cap not in profile.capabilities:
            return False

    # 检查条件
    for condition in vector.required_conditions:
        if not _evaluate_condition(condition, profile):
            return False

    return True


def _evaluate_condition(condition: str, profile: EnvironmentProfile) -> bool:
    """评估单个逃逸条件

    条件格式:
    - "privileged" → profile.is_privileged
    - "hostPID" → profile.host_pid
    - "hostNetwork" → profile.host_network
    - "hostIPC" → profile.host_ipc
    - "docker_sock" → profile.mounted_docker_sock
    - "is_container" → profile.is_container
    - "is_kubernetes" → profile.is_kubernetes
    - "cgroup_v1" → 检查 cgroup v1
    - "CAP_xxx" → 检查具体能力
    """
    condition_map = {
        "privileged": lambda: profile.is_privileged,
        "hostPID": lambda: profile.host_pid,
        "hostNetwork": lambda: profile.host_network,
        "hostIPC": lambda: profile.host_ipc,
        "docker_sock": lambda: profile.mounted_docker_sock,
        "is_container": lambda: profile.is_container,
        "is_kubernetes": lambda: profile.is_kubernetes,
    }

    if condition in condition_map:
        return condition_map[condition]()

    # 检查 CAP_xxx 能力
    if condition.startswith("CAP_"):
        return condition in profile.capabilities

    # 检查 cgroup v1
    if condition == "cgroup_v1":
        return _check_cgroup_v1()

    return False


def _check_cgroup_v1() -> bool:
    """检查是否使用 cgroup v1（cgroup v2 不受 CVE-2022-0492 影响）"""
    try:
        with open("/proc/filesystems", "r") as f:
            if "cgroup2" in f.read():
                return False  # cgroup v2
    except (FileNotFoundError, PermissionError):
        pass

    try:
        with open("/proc/self/cgroup", "r") as f:
            # cgroup v1 的典型格式
            content = f.read()
            if "cgroup2" not in content and "0::" not in content:
                return True
    except (FileNotFoundError, PermissionError):
        pass

    return False


def get_escape_risk_assessment(profile: EnvironmentProfile) -> dict:
    """综合逃逸风险评估

    Returns:
        {"total_vectors": int, "critical": int, "high": int, "summary": str}
    """
    vectors = detect_escape_vectors(profile)

    assessment: dict[str, Any] = {
        "total_vectors": len(vectors),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "vectors": [{"id": v.id, "name": v.name, "cve": v.cve} for v in vectors],
    }

    for v in vectors:
        if v.success_rate == "high" or v.detection_difficulty == "hard":
            assessment["critical"] += 1
        elif v.success_rate == "medium":
            assessment["high"] += 1
        else:
            assessment["medium"] += 1

    if assessment["critical"] > 2:
        assessment["summary"] = "极度危险：当前环境暴露多个高成功率逃逸向量"
    elif assessment["critical"] > 0:
        assessment["summary"] = "高危：存在至少一个可直接利用的逃逸路径"
    elif assessment["high"] > 0:
        assessment["summary"] = "中等风险：存在潜在逃逸向量，需特定条件"
    elif assessment["total_vectors"] > 0:
        assessment["summary"] = "低风险：存在理论逃逸路径但条件苛刻"
    else:
        assessment["summary"] = "安全：未发现已知逃逸向量"

    return assessment
