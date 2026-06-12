"""网络攻击面分析

收录 DNS 劫持、CNI 篡改、Service Mesh 利用等网络层攻击技术。
"""

from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel


NETWORK_VECTORS: list[AttackVector] = [
    AttackVector(
        id="NET-001",
        name="CoreDNS ConfigMap 劫持 - 全集群 DNS 投毒",
        phase=AttackPhase.INITIAL_ACCESS,
        risk=RiskLevel.CRITICAL,
        description=(
            "修改 coredns ConfigMap，插入 rewrite 规则将特定域名（如 API Server 地址、"
            "元数据服务、镜像仓库）解析到攻击者控制的 IP。"
            "CoreDNS 自动重载配置，无需重启 Pod，单步原子操作。"
        ),
        prerequisites=["修改 coredns ConfigMap 的权限"],
        steps=[
            "kubectl edit configmap coredns -n kube-system",
            "在 Corefile 中插入 rewrite name api-server.example.com attacker-ip",
            "CoreDNS 自动重载",
            "集群内 Pod 的 DNS 查询返回攻击者 IP",
            "实施中间人攻击或凭证窃取",
        ],
        detection_hints=[
            "coredns ConfigMap 变更",
            "DNS 响应 IP 异常",
            "CoreDNS 重载事件",
        ],
        references=["CoreDNS rewrite plugin"],
    ),
    AttackVector(
        id="NET-002",
        name="kube-proxy iptables 规则篡改",
        phase=AttackPhase.LATERAL_MOVEMENT,
        risk=RiskLevel.HIGH,
        description=(
            "在节点上直接插入 iptables NAT 规则，将目标为特定 Service ClusterIP 的流量"
            "静默重定向到攻击者 Pod。不影响 Service 原有功能，插入迅速。"
            "配合 DNS 劫持效果更佳。"
        ),
        prerequisites=["节点 root 权限", "iptables 可用"],
        steps=[
            "定位目标 Service ClusterIP",
            "iptables -t nat -A KUBE-SERVICES -d <ClusterIP> -j DNAT --to <attacker-pod-ip>",
            "在攻击者 Pod 内部署流量代理",
            "透明转发或篡改流量",
        ],
        detection_hints=[
            "异常 iptables NAT 规则",
            "Service 流量监控异常",
        ],
    ),
    AttackVector(
        id="NET-003",
        name="Istio/EnvoyFilter 全局流量劫持",
        phase=AttackPhase.LATERAL_MOVEMENT,
        risk=RiskLevel.CRITICAL,
        description=(
            "创建 EnvoyFilter CR，对所有 Sidecar 的流量执行自定义操作："
            "重定向到攻击者 ext_authz 服务、注入 lua 脚本篡改请求/响应、"
            "复制流量至外部收集器。"
        ),
        prerequisites=["创建 EnvoyFilter 的权限", "Istio 环境"],
        steps=[
            "创建 EnvoyFilter CR，workloadSelector: {}  全局匹配",
            "配置 filter 类型为 ext_authz 或 lua",
            "指向攻击者控制的 gRPC/HTTP 服务",
            "Sidecar 自动应用新 filter",
            "所有经过 Sidecar 的流量被劫持",
        ],
        detection_hints=[
            "异常 EnvoyFilter 对象",
            "Sidecar filter 链变更",
            "流量流向异常地址",
        ],
        references=["Istio EnvoyFilter API"],
    ),
    AttackVector(
        id="NET-004",
        name="Istio CA 证书伪造 (SPIFFE ID 欺骗)",
        phase=AttackPhase.CREDENTIAL_ACCESS,
        risk=RiskLevel.CRITICAL,
        description=(
            "Istio CA 默认用 Kubernetes CSR 签发工作负载证书。"
            "利用 Kubelet CSR 技巧伪造任意 SPIFFE ID 的证书"
            "（如 spiffe://cluster.local/ns/kube-system/sa/default），"
            "突破 mTLS 信任边界。"
        ),
        prerequisites=["Kubelet 证书或 CSR 创建权限", "Istio 环境"],
        steps=[
            "获取 Kubelet 客户端证书",
            "创建 CSR 申请特定 SPIFFE ID 的证书",
            "或直接向 Istio CA 发起证书签名请求",
            "使用伪造证书访问其他 mTLS 保护的服务",
        ],
        detection_hints=[
            "异常 SPIFFE ID 证书",
            "CSR 中的异常 SAN",
        ],
    ),
    AttackVector(
        id="NET-005",
        name="mTLS 降级攻击",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.HIGH,
        description=(
            "修改 Istio PeerAuthentication 策略从 STRICT 改为 PERMISSIVE，"
            "让原本强制 mTLS 的服务间通信降级为允许明文。"
            "攻击者可以进行流量嗅探和篡改。"
        ),
        prerequisites=["修改 PeerAuthentication 的权限", "Istio 环境"],
        steps=[
            "kubectl get peerauthentication -A",
            "修改策略 mode: PERMISSIVE",
            "原本 mTLS 保护的流量变为明文",
            "在集群内嗅探/篡改流量",
        ],
        detection_hints=[
            "PeerAuthentication 策略变更",
            "mTLS 模式降级",
        ],
    ),
    AttackVector(
        id="NET-006",
        name="Calico BGP 路由劫持",
        phase=AttackPhase.LATERAL_MOVEMENT,
        risk=RiskLevel.HIGH,
        description=(
            "修改 Calico IPPool 或 BGPPeer 配置，宣告错误路由。"
            "Service ClusterIP 流量被引向攻击者控制的节点或 Pod。"
            "利用 BGP 协议信任特性，影响范围可达整个集群。"
        ),
        prerequisites=["修改 Calico CR 的权限", "Calico BGP 模式"],
        steps=[
            "kubectl get ippool,bgppeer",
            "修改 IPPool 或创建伪造 BGPPeer",
            "BGP 路由传播到所有节点",
            "目标流量被路由到攻击者 IP",
        ],
        detection_hints=[
            "异常 BGP 路由表项",
            "IPPool/BGPPeer 配置变更",
        ],
    ),
    AttackVector(
        id="NET-007",
        name="Cilium eBPF Map 篡改",
        phase=AttackPhase.LATERAL_MOVEMENT,
        risk=RiskLevel.HIGH,
        description=(
            "Cilium 使用 eBPF map 存储负载均衡和网络策略。"
            "在节点上通过 bpftool 直接修改 eBPF map 条目，"
            "实现精准流量劫持，绕过所有 Kubernetes 层审计。"
        ),
        prerequisites=["节点 root 权限", "Cilium CNI", "bpftool"],
        steps=[
            "逃逸至宿主机",
            "bpftool map list | grep cilium",
            "bpftool map dump id <lb_map_id>",
            "bpftool map update id <lb_map_id> key <hex> value <hex>",
            "流量在 eBPF 层被重定向",
        ],
        detection_hints=[
            "eBPF map 异常修改",
            "bpftool 使用痕迹",
        ],
        references=["Cilium eBPF datapath"],
    ),
    AttackVector(
        id="NET-008",
        name="Flannel/Overlay ARP 欺骗",
        phase=AttackPhase.LATERAL_MOVEMENT,
        risk=RiskLevel.MEDIUM,
        description=(
            "在 Flannel vxlan 或 host-gw 模式中，Pod 在同一 L2 网段时，"
            "可以通过发送伪造 gratuitous ARP 将其他 Pod 的 IP 指向自己的 MAC。"
            "实施 Pod 级别的中间人攻击。"
        ),
        prerequisites=["Pod 在 Flat 网络模式", "arping 可用"],
        steps=[
            "确认同节点或同 L2 段的目标 Pod IP",
            "arping -c 3 -S <目标IP> -s <攻击者IP> -i eth0 <目标IP>",
            "目标 Pod 流量被错误路由",
            "实施流量嗅探或篡改",
        ],
        detection_hints=[
            "ARP 表异常",
            "网络层包异常",
        ],
    ),
]


def get_network_by_type(atk_type: str) -> list[AttackVector]:
    """按网络攻击类型筛选"""
    type_map = {
        "dns": ["CoreDNS", "DNS"],
        "service_mesh": ["Istio", "Envoy", "Sidecar", "mTLS"],
        "cni": ["Calico", "Cilium", "Flannel"],
        "iptables": ["iptables", "kube-proxy"],
    }
    if atk_type in type_map:
        keywords = type_map[atk_type]
        return [
            v for v in NETWORK_VECTORS
            if any(kw in v.description or kw in v.name for kw in keywords)
        ]
    return NETWORK_VECTORS
