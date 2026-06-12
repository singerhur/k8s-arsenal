"""云平台模块

云平台集成：AWS / GCP / Azure 元数据服务探测与凭证窃取。
"""

from k8s_arsenal.cloud.base import CloudMetadataBase, CloudCredential
from k8s_arsenal.cloud.aws import AWSExploit, check_aws_irsa_risk
from k8s_arsenal.cloud.azure import AzureExploit, check_aks_risk
from k8s_arsenal.cloud.gcp import GCPExploit, check_gke_risk
from k8s_arsenal.cloud.alibaba import AlibabaExploit, check_ack_risk

__all__ = [
    "CloudCredential",
    "CloudMetadataBase",
    "AlibabaExploit",
    "AWSExploit",
    "AzureExploit",
    "GCPExploit",
    "check_ack_risk",
    "check_aks_risk",
    "check_aws_irsa_risk",
    "check_gke_risk",
]
