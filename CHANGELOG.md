# Changelog

All notable changes to K8s Arsenal will be documented in this file.

## [0.4.0] - 2026-06-07

### Added
- PlaybookExecutor: 攻击检测→可执行命令，支持 --run / --stealth / --list-commands / --dry-run
- _VECTOR_ID_MAP: 直接 ID 映射表，消除命令匹配误/漏

### Fixed
- 命令关键字误匹配（P0）: _get_vector_command() 子串匹配导致 3 个向量返回 None（ESC-007/008/011），ESC-002 拿错命令 → 改用 _VECTOR_ID_MAP 直接 ID 映射
- 自检身份字段为空（P0）: _build_report() 直接 os.environ.get() 绕过 _check_identity() 解析结果 → 存储实例属性并复用
- Docker 内置 docker.io 包（CRI Socket 检测）
- catalog --phase 别名支持
- 靶场环境识别中文指纹匹配
- nginx:alpine → k8s-arsenal-pod:latest（国内镜像兼容）

### Changed
- executor.py 命令映射三合为一（_ESCAPE_COMMANDS 类常量）
- 7 个子模块 __init__.py 正式导出（advanced/evasion/lateral/network/persistence/supply_chain/utils）
- 清除死依赖 jinja2/python-dateutil
- 测试覆盖 200 用例（+65 新增）

## [0.3.0] - 2026-06-06

### Added
- 智能适应引擎（AdaptiveEngine）
- 攻击向量优化器（AttackVectorOptimizer）
- SmartAttackChain 加权评分排序

## [0.2.0] - 2026-06-05

### Added
- 基础攻击向量编目（72 项）
- 信任拓扑映射（trust-map）
- Pod 自检扫描（self-check）

## [0.1.0] - 2026-06-05

### Added
- 初始项目结构
- 基础环境探测（recon）
- 攻击面评估（assess）