"""检测逃逸技术编目

收录绕过 K8s 审计日志、运行时安全工具（Falco/Tetragon）的对抗技术。
"""

from k8s_arsenal.models import AttackVector, AttackPhase, RiskLevel


EVASION_VECTORS: list[AttackVector] = [
    AttackVector(
        id="EVA-001",
        name="子资源审计绕过",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.HIGH,
        description=(
            "利用 pods/exec、pods/log、nodes/proxy 等子资源端点进行操作。"
            "子资源的审计日志格式与普通 CRUD 不同，很多 SIEM 规则只匹配了 create/update/delete。"
        ),
        prerequisites=["API Server 访问权限"],
        steps=[
            "使用 pods/exec 而非直接访问 API",
            "通过 nodes/proxy 间接操作",
            "利用子资源审计格式差异绕过检测规则",
        ],
        detection_hints=[
            "审计日志中子资源操作的异常频率",
            "非运维时间的大量 exec/log 操作",
        ],
        references=["K8s Audit Policy"],
    ),
    AttackVector(
        id="EVA-002",
        name="Impersonation 身份混淆",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.HIGH,
        description=(
            "在多次 API 操作中交替使用 Impersonate-User 和自己直接操作。"
            "让溯源者无法确定真实攻击者身份。"
            "将恶意操作混入正常 Impersonation 使用模式中。"
        ),
        prerequisites=["有 impersonate 权限的 SA 或用户"],
        steps=[
            "操作1: 直接使用原始 SA 执行侦查",
            "操作2: Impersonate system:admin 执行关键操作",
            "操作3: 换回原始 SA 执行正常操作",
            "在审计日志中制造身份混乱",
        ],
        detection_hints=[
            "同一来源 IP 的多重身份切换",
            "Impersonation 操作的异常模式",
        ],
    ),
    AttackVector(
        id="EVA-003",
        name="kubelet 日志轰炸混淆",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.MEDIUM,
        description=(
            "大量 kubectl exec 或 kubectl port-forward 操作产生大量审计日志。"
            "将关键恶意操作淹没在噪音中。"
            "人类审计员面对海量 exec 记录时容易遗漏。"
        ),
        prerequisites=["logs/exec 权限", "大规模操作能力"],
        steps=[
            "先执行 100+ 次正常 exec/log 操作",
            "在噪音中夹杂 1-2 次恶意操作",
            "利用审计日志的体量疲劳效应",
        ],
        detection_hints=[
            "exec/log 操作的突发峰值",
            "操作频率与业务节律不匹配",
        ],
    ),
    AttackVector(
        id="EVA-004",
        name="Falco 绕过 - 非 execve 执行",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.HIGH,
        description=(
            "Falco 的 spawned_process 规则依赖 execve 系统调用。"
            "使用 Python ctypes 直接调用 syscall，Go syscall.RawSyscall，"
            "或记忆体加载 ELF 载荷，不触发 execve 事件。"
        ),
        prerequisites=["容器内代码执行能力"],
        steps=[
            "Python: ctypes.CDLL(None).syscall(SYS_execve, ...)",
            "Go: syscall.RawSyscall 直接执行",
            "使用 memfd_create + fexecve 内存执行",
            "所有操作绕过 execve hook",
        ],
        detection_hints=[
            "异常 syscall 序列",
            "无 execve 却有 network 事件的进程",
        ],
        references=["Falco default rules", "eBPF hook points"],
    ),
    AttackVector(
        id="EVA-005",
        name="Falco 白名单路径利用",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.MEDIUM,
        description=(
            "Falco 默认规则信任 /usr/bin/ 和 /bin/ 下的已知程序。"
            "将恶意工具复制到白名单路径，或将后门注入到白名单程序（LD_PRELOAD）。"
        ),
        prerequisites=["/usr/bin 或 /bin 可写"],
        steps=[
            "cp /tmp/malware /usr/bin/kubectl-node",
            "或使用 LD_PRELOAD 注入白名单程序",
            "Falco 跳过白名单路径的事件",
        ],
        detection_hints=[
            "白名单路径文件完整性变更",
            "LD_PRELOAD 环境变量",
        ],
        references=["Falco trusted paths config"],
    ),
    AttackVector(
        id="EVA-006",
        name="Tetragon TracingPolicy 感知绕过",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.MEDIUM,
        description=(
            "先读取集群中的 TracingPolicy CRD，了解哪些系统调用被 hook。"
            "避开被监控的 syscall，选择未被覆盖的攻击面进行利用。"
        ),
        prerequisites=["可读取 TracingPolicy CRD"],
        steps=[
            "kubectl get tracingpolicies -A",
            "分析被 hook 的系统调用列表",
            "选择未被监控的 syscall 执行操作",
        ],
        detection_hints=[
            "TracingPolicy 读取操作",
            "已知攻击 syscall 的缺失",
        ],
        references=["Tetragon TracingPolicy"],
    ),
    AttackVector(
        id="EVA-007",
        name="时区混淆 - UTC vs 本地时间",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.LOW,
        description=(
            "利用审计日志中 UTC 时间与本地时间（如 Asia/Shanghai）的差异。"
            "选择在 UTC 深夜但本地工作时间操作，"
            "或反之在 UTC 工作时间但本地深夜操作。"
            "制造'不可能在此时操作'的误判。"
        ),
        prerequisites=["对目标运维时间有了解"],
        steps=[
            "了解目标运维窗口（如 9:00-18:00 CST = 1:00-10:00 UTC）",
            "在 UTC 和 CST 的交叉时间窗操作",
            "攻击时间表面在非运维窗口",
        ],
        detection_hints=[
            "审计日志时区与本地时间的不一致",
        ],
    ),
    AttackVector(
        id="EVA-008",
        name="Secret Controller 绕过 - TokenRequest",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.HIGH,
        description=(
            "使用 TokenRequest API 而非创建 Secret 获取 SA Token。"
            "Token 不存在于 etcd 的 Secret 对象中，secret scanner 无法检测。"
            "规避了 Secret 生命周期管理和监控。"
        ),
        prerequisites=["API Server 访问", "可创建 TokenRequest"],
        steps=[
            "使用 TokenRequest API 直接请求 token",
            "不创建 Secret 对象",
            "Token 仅存于内存",
            "绕过 Secret 监控和轮换检测",
        ],
        detection_hints=[
            "TokenRequest API 调用记录",
            "无对应 Secret 的 Token 使用",
        ],
        references=["K8s TokenRequest API"],
    ),
    AttackVector(
        id="EVA-009",
        name="RBAC 权限碰撞检测规避",
        phase=AttackPhase.DEFENSE_EVASION,
        risk=RiskLevel.LOW,
        description=(
            "先用 kubectl auth can-i --list 枚举所有可用权限，"
            "只使用实际已授权的操作。"
            "避免触发 403 Forbidden（强制 RBAC 检测的典型信号）。"
        ),
        prerequisites=["API Server 访问"],
        steps=[
            "kubectl auth can-i --list",
            "解析权限列表",
            "只执行已授权的操作",
            "从不触发 403",
        ],
        detection_hints=[
            "auth can-i --list 调用",
            "权限枚举行为",
        ],
    ),
]


def get_evasion_by_target(target: str) -> list[AttackVector]:
    """按绕过目标筛选"""
    target_map = {
        "audit": ["审计", "audit", "日志"],
        "falco": ["Falco", "falco"],
        "tetragon": ["Tetragon", "TracingPolicy"],
        "rbac": ["RBAC", "auth"],
        "secret": ["Secret", "Token"],
    }
    if target in target_map:
        keywords = target_map[target]
        return [
            v for v in EVASION_VECTORS
            if any(kw.lower() in v.description.lower() for kw in keywords)
        ]
    return EVASION_VECTORS
