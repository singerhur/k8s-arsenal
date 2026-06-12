"""云平台元数据服务基类

统一抽象各云平台 IMDS（Instance Metadata Service）访问接口。
"""

import abc
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CloudCredential:
    """云平台临时凭证"""
    provider: str
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    expires_at: Optional[str] = None
    identity_token: Optional[str] = None
    extra: dict = field(default_factory=dict)


class CloudMetadataBase(abc.ABC):
    """云平台元数据服务抽象基类"""

    @abc.abstractmethod
    def detect(self) -> bool:
        """检测是否运行在该云平台"""
        ...

    @abc.abstractmethod
    def get_credentials(self) -> Optional[CloudCredential]:
        """获取临时凭证"""
        ...

    @abc.abstractmethod
    def get_instance_info(self) -> dict:
        """获取实例信息"""
        ...

    @staticmethod
    def _http_get(url: str, headers: Optional[dict] = None, timeout: int = 2) -> Optional[str]:
        """HTTP GET 请求，超时返回 None"""
        try:
            import requests
            resp = requests.get(url, headers=headers or {}, timeout=timeout)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None

    @staticmethod
    def _http_put(url: str, headers: Optional[dict] = None, timeout: int = 2) -> Optional[str]:
        """HTTP PUT 请求"""
        try:
            import requests
            resp = requests.put(url, headers=headers or {}, timeout=timeout)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None
