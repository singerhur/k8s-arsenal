"""性能监控与结构化日志

提供轻量级的执行计时、调用追踪和结构化日志功能。
零外部依赖，仅使用 Python 标准库。
"""

from __future__ import annotations

import functools
import json
import logging
import sys
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional, TypeVar

# ── 日志初始化 ──────────────────────────────────────────────────

def _setup_logger(name: str = "k8s_arsenal") -> logging.Logger:
    """创建结构化 logger"""
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            fmt="%(asctime)s [%(levelname)-5s] %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.WARNING)

    return logger


_log = _setup_logger()


def set_log_level(level: str) -> None:
    """设置日志级别: DEBUG, INFO, WARNING, ERROR"""
    _log.setLevel(getattr(logging, level.upper(), logging.WARNING))


# ── 性能记录 ────────────────────────────────────────────────────

@dataclass
class PerfRecord:
    """单次函数调用性能记录"""
    function: str
    module: str
    start_time: str          # ISO 时间戳
    duration_ms: float
    success: bool
    error: str = ""
    args_summary: str = ""   # 参数摘要（不记录敏感信息）
    memory_delta_kb: float = 0.0


@dataclass
class PerfStats:
    """累积性能统计"""
    function: str
    call_count: int = 0
    total_duration_ms: float = 0.0
    min_duration_ms: float = float("inf")
    max_duration_ms: float = 0.0
    error_count: int = 0
    records: list[PerfRecord] = field(default_factory=list, repr=False)

    @property
    def avg_duration_ms(self) -> float:
        return self.total_duration_ms / max(self.call_count, 1)

    def merge(self, record: PerfRecord) -> None:
        self.call_count += 1
        self.total_duration_ms += record.duration_ms
        self.min_duration_ms = min(self.min_duration_ms, record.duration_ms)
        self.max_duration_ms = max(self.max_duration_ms, record.duration_ms)
        if not record.success:
            self.error_count += 1
        self.records.append(record)


# 全局性能注册表
_PERF_REGISTRY: dict[str, PerfStats] = {}
F = TypeVar("F", bound=Callable[..., Any])


def timed(
    threshold_ms: float = 0.0,
    log_args: bool = False,
    record: bool = True,
) -> Callable[[F], F]:
    """性能计时装饰器

    Args:
        threshold_ms: 超过此阈值才输出警告日志（0 = always log）
        log_args: 是否在日志中记录调用参数
        record: 是否记录到性能注册表
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            success = True
            error_msg = ""

            try:
                result = func(*args, **kwargs)
                return result
            except Exception:
                success = False
                error_msg = traceback.format_exc()
                raise
            finally:
                elapsed = (time.perf_counter() - start) * 1000
                qualname = f"{func.__module__}.{func.__qualname__}"

                if elapsed >= threshold_ms:
                    level = "WARNING" if elapsed > 1000 else "DEBUG"
                    args_str = ""
                    if log_args:
                        args_str = f" args={args!r}" if args else ""
                        if kwargs:
                            args_str += f" kwargs={kwargs!r}"
                    getattr(_log, level.lower())(
                        f"{qualname} took {elapsed:.2f}ms{args_str}"
                    )

                if record:
                    rec = PerfRecord(
                        function=qualname,
                        module=func.__module__,
                        start_time=datetime.now(timezone.utc).isoformat(),
                        duration_ms=elapsed,
                        success=success,
                        error=error_msg[:200] if error_msg else "",
                        args_summary=f"{len(args)} args, {len(kwargs)} kwargs" if log_args else "",
                    )
                    if qualname not in _PERF_REGISTRY:
                        _PERF_REGISTRY[qualname] = PerfStats(function=qualname)
                    _PERF_REGISTRY[qualname].merge(rec)

        return wrapper  # type: ignore[return-value]

    return decorator


@contextmanager
def perf_timer(name: str, extra: Optional[dict[str, Any]] = None):
    """上下文管理器 — 代码块计时

    Usage:
        with perf_timer("heavy_operation"):
            do_work()
    """
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = (time.perf_counter() - start) * 1000
        extra_str = f" | {json.dumps(extra)}" if extra else ""
        _log.debug(f"[BLOCK] {name} took {elapsed:.2f}ms{extra_str}")


def get_perf_report(sort_by: str = "total_duration_ms") -> str:
    """生成性能报告（纯文本，供 CLI 展示）"""
    if not _PERF_REGISTRY:
        return "No performance records yet."

    stats = sorted(
        _PERF_REGISTRY.values(),
        key=lambda s: getattr(s, sort_by),
        reverse=True,
    )

    lines = [
        f"{'Function':<55} {'Calls':>6} {'Total (ms)':>11} {'Avg (ms)':>9} {'Min (ms)':>9} {'Max (ms)':>9} {'Errors':>7}",
        "-" * 110,
    ]
    for s in stats:
        lines.append(
            f"{s.function:<55} {s.call_count:>6} {s.total_duration_ms:>11.2f} "
            f"{s.avg_duration_ms:>9.2f} {s.min_duration_ms:>9.2f} "
            f"{s.max_duration_ms if s.max_duration_ms != float('inf') else 0.0:>9.2f} "
            f"{s.error_count:>7}"
        )

    total_calls = sum(s.call_count for s in stats)
    total_time = sum(s.total_duration_ms for s in stats)
    total_errors = sum(s.error_count for s in stats)
    lines.append("-" * 110)
    lines.append(
        f"{'TOTAL':<55} {total_calls:>6} {total_time:>11.2f} "
        f"{'':>9} {'':>9} {'':>9} {total_errors:>7}"
    )

    return "\n".join(lines)


def reset_perf_stats() -> None:
    """重置性能统计"""
    _PERF_REGISTRY.clear()


# ── 结构化日志 ──────────────────────────────────────────────────

class StructuredLogger:
    """结构化日志记录器

    提供统一的键值对日志格式，便于下游解析。
    """

    def __init__(self, name: str = "k8s_arsenal"):
        self._logger = logging.getLogger(name)

    def debug(self, msg: str, **kwargs: Any) -> None:
        self._log("DEBUG", msg, **kwargs)

    def info(self, msg: str, **kwargs: Any) -> None:
        self._log("INFO", msg, **kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._log("WARNING", msg, **kwargs)

    def error(self, msg: str, **kwargs: Any) -> None:
        self._log("ERROR", msg, **kwargs)

    def critical(self, msg: str, **kwargs: Any) -> None:
        self._log("CRITICAL", msg, **kwargs)

    def event(self, event: str, **kwargs: Any) -> None:
        """记录结构化事件"""
        kwargs["_event"] = event
        self._log("INFO", event, **kwargs)

    def _log(self, level: str, msg: str, **kwargs: Any) -> None:
        extra = json.dumps(kwargs, ensure_ascii=False, default=str) if kwargs else ""
        getattr(self._logger, level.lower())(f"{msg}{' | ' + extra if extra else ''}")

    def exception(self, msg: str, **kwargs: Any) -> None:
        """记录异常（含堆栈）"""
        extra = json.dumps(kwargs, ensure_ascii=False, default=str) if kwargs else ""
        self._logger.exception(f"{msg}{' | ' + extra if extra else ''}")


# 模块级便捷实例
logger = StructuredLogger()


# ── 调用追踪 ────────────────────────────────────────────────────

class TraceContext:
    """轻量级调用追踪上下文

    Usage:
        trace = TraceContext("recon_scan")
        with trace.span("k8s_enum"):
            enumerate_environment()
        with trace.span("sa_analysis"):
            analyze_sa()
        trace.print_tree()
    """

    def __init__(self, root_name: str = "root"):
        self._root: dict[str, Any] = {
            "name": root_name,
            "start": time.perf_counter(),
            "children": [],
        }
        self._stack: list[dict[str, Any]] = [self._root]

    @contextmanager
    def span(self, name: str):
        node: dict[str, Any] = {
            "name": name,
            "start": time.perf_counter(),
            "children": [],
        }
        self._stack[-1]["children"].append(node)
        self._stack.append(node)
        try:
            yield
        finally:
            node["duration_ms"] = (time.perf_counter() - node["start"]) * 1000
            self._stack.pop()

    def print_tree(self) -> str:
        self._root["duration_ms"] = (time.perf_counter() - self._root["start"]) * 1000
        return self._format_node(self._root, 0)

    def _format_node(self, node: dict[str, Any], depth: int) -> str:
        indent = "  " * depth
        dur = node.get("duration_ms", 0)
        prefix = "├─" if depth > 0 else ""
        lines = [f"{indent}{prefix}{node['name']} ({dur:.2f}ms)"]
        for child in node.get("children", []):
            lines.append(self._format_node(child, depth + 1))
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        self._root["duration_ms"] = (time.perf_counter() - self._root["start"]) * 1000
        return self._root
