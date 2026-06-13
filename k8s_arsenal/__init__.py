"""K8s Arsenal - 云原生攻击面分析工具

基于"云原生攻击战术思路总纲"构建的 K8s 安全评估工具。
用于红蓝对抗中的攻击面枚举、信任链映射、攻击路径规划与战术编目。

模块结构:
    recon       - 侦察枚举：K8s 环境探测、RBAC 分析、信任拓扑映射
    escape      - 容器逃逸：逃逸条件检测与技术编目
    persistence - 持久化：后门持久化技术编目
    lateral     - 横向移动：横向移动攻击路径分析
    network     - 网络攻击：DNS/CNI/ServiceMesh 劫持分析
    cloud       - 云平台：AWS/GCP/Azure IAM 利用链
    evasion     - 检测逃逸：审计日志与运行时安全工具绕过
    playbook    - 攻击剧本：攻击链模板与组合路径生成
    supply_chain - 供应链：Helm/镜像/Operator 投毒分析
"""

__version__ = "0.9.0"
__author__ = "QClaw Security Lab"
__description__ = "Kubernetes Attack Surface Analyzer & Red Team Playbook"
