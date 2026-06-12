"""ServiceAccount 权限分析

分析当前 ServiceAccount 的 RBAC 权限，识别高风险权限组合。
"""

from typing import Optional, Any

try:
    from kubernetes import client, config
    HAS_K8S_CLIENT = True
except ImportError:
    HAS_K8S_CLIENT = False

from k8s_arsenal.models import SAResult


# 高风险权限列表（可能导致提权或集群控制）
HIGH_RISK_PERMISSIONS = {
    # 资源级
    "secrets": ["get", "list", "watch"],
    "configmaps": ["get", "list", "create", "update"],
    "serviceaccounts": ["create", "update", "patch", "impersonate"],
    "pods": ["create", "update", "patch", "delete", "exec"],
    "pods/exec": ["create"],
    "pods/log": ["get"],
    "deployments": ["create", "update", "patch", "delete"],
    "daemonsets": ["create", "update", "patch"],
    "roles": ["bind", "escalate"],
    "clusterroles": ["bind", "escalate"],
    "nodes": ["get", "list", "proxy"],
    "nodes/proxy": ["get", "create"],
    "namespaces": ["create", "delete"],
    "mutatingwebhookconfigurations": ["create", "update", "patch"],
    "validatingwebhookconfigurations": ["create", "update", "patch"],
    "certificatesigningrequests": ["create", "update", "approve"],
    # 非资源级
    "certificatesigningrequests/approval": ["create", "update"],
}

# 直接等于 cluster-admin 的权限
CLUSTER_ADMIN_VERBS = {"*"}
CLUSTER_ADMIN_RESOURCES = {"*"}


def analyze_current_sa(kubeconfig: Optional[str] = None) -> Optional[SAResult]:
    """分析当前 Pod 的 ServiceAccount 权限

    如果运行在 K8s 集群内，自动使用 in-cluster 配置。
    否则使用 kubeconfig 或默认配置。

    Returns:
        SAResult 或 None（如果无法连接 K8s API）
    """
    if not HAS_K8S_CLIENT:
        return _analyze_fallback()

    try:
        # 加载配置
        if kubeconfig:
            config.load_kube_config(config_file=kubeconfig)
        else:
            try:
                config.load_incluster_config()
            except config.ConfigException:
                config.load_kube_config()

        auth_api = client.AuthorizationV1Api()

        # 获取当前 SA 信息
        sa_result = SAResult(
            name=_get_sa_name(),
            namespace=_get_namespace(),
        )

        # 检查高风险权限
        for resource, verbs in HIGH_RISK_PERMISSIONS.items():
            # 处理子资源（如 pods/exec）
            parts = resource.split("/")
            resource_name = parts[0]
            subresource = parts[1] if len(parts) > 1 else None

            for verb in verbs:
                try:
                    spec = client.V1SelfSubjectAccessReviewSpec(
                        resource_attributes=client.V1ResourceAttributes(
                            verb=verb,
                            resource=resource_name,
                            subresource=subresource,
                        )
                    )
                    body = client.V1SelfSubjectAccessReview(spec=spec)
                    resp = auth_api.create_self_subject_access_review(body)

                    if resp.status.allowed:
                        desc = f"{verb} {resource}"
                        sa_result.powerful_permissions.append(desc)
                except client.ApiException:
                    pass

        # 检查 cluster-admin 级别权限
        sa_result.is_high_risk = len(sa_result.powerful_permissions) > 0
        if sa_result.is_high_risk:
            sa_result.risk_detail = (
                f"SA {sa_result.name} 在命名空间 {sa_result.namespace} "
                f"拥有 {len(sa_result.powerful_permissions)} 项高风险权限"
            )

        return sa_result

    except Exception:
        return _analyze_fallback()


def _get_sa_name() -> str:
    """获取当前 ServiceAccount 名称"""
    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r") as f:
            ns = f.read().strip()
        import socket
        return f"sa-in-pod-{socket.gethostname()}"
    except Exception:
        return "unknown-sa"


def _get_namespace() -> str:
    """获取当前命名空间"""
    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r") as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def _analyze_fallback() -> Optional[SAResult]:
    """离线回退分析 - 仅从 Token 推断"""
    sa_path = "/var/run/secrets/kubernetes.io/serviceaccount"
    import os
    if not os.path.exists(sa_path):
        return None

    result = SAResult(
        name="unknown (离线模式)",
        namespace=_get_namespace(),
    )
    result.risk_detail = "离线模式：无法查询 K8s API 进行实时权限分析。请安装 kubernetes 客户端库或在集群内运行。"
    return result


# --- 静态分析工具 ---

def assess_permission_risk(
    resource: str,
    verbs: list[str],
    namespace: str = "any"
) -> dict[str, str]:
    """静态评估权限组合风险

    Args:
        resource: K8s 资源类型
        verbs: 操作动词列表
        namespace: 命名空间限制

    Returns:
        {"risk": "high/medium/low", "reason": "...", "attack_path": "..."}
    """
    result = {"risk": "low", "reason": "", "attack_path": ""}

    # cluster-admin 直接
    if "*" in verbs or resource == "*":
        result["risk"] = "critical"
        result["reason"] = f"完全控制: {resource}"
        result["attack_path"] = "直接创建 cluster-admin 绑定"
        return result

    # 按资源评估
    assessments: dict[str, dict[str, Any]] = {
        "pods/exec": {
            "risk": "high",
            "reason": "可 exec 进入任意 Pod → 窃取 Token/凭证",
            "verbs": ["create"],
        },
        "pods": {
            "risk": "high",
            "reason": "可创建特权 Pod → 逃逸宿主机",
            "verbs": ["create", "update", "patch"],
        },
        "nodes/proxy": {
            "risk": "critical",
            "reason": "Kubelet API 代理 → 直接访问节点",
            "verbs": ["get", "create"],
        },
        "secrets": {
            "risk": "high",
            "reason": "可读取任意 Secret → 窃取 SA Token 和证书",
            "verbs": ["get", "list"],
        },
        "mutatingwebhookconfigurations": {
            "risk": "critical",
            "reason": "可创建 Admission Webhook → 全集群后门",
            "verbs": ["create", "update"],
        },
        "certificatesigningrequests": {
            "risk": "high",
            "reason": "可申请客户端证书 → 身份伪造",
            "verbs": ["create"],
        },
        "clusterroles": {
            "risk": "critical",
            "reason": "可创建新 ClusterRole 或提升权限",
            "verbs": ["create", "update", "bind", "escalate"],
        },
    }

    if resource in assessments:
        a = assessments[resource]
        for v in verbs:
            if v in a["verbs"]:
                result["risk"] = a["risk"]
                result["reason"] = a["reason"]
                break

    return result
