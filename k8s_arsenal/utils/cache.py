"""缓存工具

提供内存缓存和可选磁盘缓存，加速重复评分和编目查询。
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import pickle
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar, Dict

F = TypeVar("F", bound=Callable[..., Any])

# ── 内存 LRU 缓存 ──────────────────────────────────────────────

_mem_cache: Dict[str, tuple[float, Any]] = {}
_mem_cache_max_size: int = 512
_mem_cache_ttl: float = 300.0


def set_mem_cache_config(max_size: int = 512, ttl: float = 300.0) -> None:
    """配置内存缓存"""
    global _mem_cache_max_size, _mem_cache_ttl
    _mem_cache_max_size = max_size
    _mem_cache_ttl = ttl


def mem_cache_get(key: str) -> Optional[Any]:
    """从内存缓存获取"""
    if key not in _mem_cache:
        return None
    ts, val = _mem_cache[key]
    if time.time() - ts > _mem_cache_ttl:
        del _mem_cache[key]
        return None
    return val


def mem_cache_set(key: str, value: Any) -> None:
    """写入内存缓存（自动 LRU 淘汰）"""
    if len(_mem_cache) >= _mem_cache_max_size:
        oldest = min(_mem_cache, key=lambda k: _mem_cache[k][0])
        del _mem_cache[oldest]
    _mem_cache[key] = (time.time(), value)


def mem_cache_clear() -> int:
    """清空内存缓存"""
    count = len(_mem_cache)
    _mem_cache.clear()
    return count


def _make_hash(*args: Any, **kwargs: Any) -> str:
    """生成缓存键"""
    raw = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, default=str)
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def cached(ttl: Optional[float] = None):
    """函数结果缓存装饰器（内存 LRU）"""

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            key = f"{func.__module__}.{func.__qualname__}:{_make_hash(*args, **kwargs)}"
            result = mem_cache_get(key)
            if result is not None:
                return result
            result = func(*args, **kwargs)
            mem_cache_set(key, result)
            return result

        return wrapper  # type: ignore[return-value]

    return decorator


# ── 磁盘缓存 ────────────────────────────────────────────────────

class DiskCache:
    """可选磁盘缓存，CI/CD 场景保持跨进程状态"""

    def __init__(self, cache_dir: Optional[str] = None):
        if cache_dir is None:
            cache_dir = os.path.join(tempfile.gettempdir(), "k8s-arsenal-cache")
        self._dir = Path(cache_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def get(self, key: str, max_age_s: float = 3600.0) -> Optional[Any]:
        path = self._dir / f"{key}.pkl"
        if not path.exists():
            return None
        if time.time() - path.stat().st_mtime > max_age_s:
            try:
                path.unlink(missing_ok=True)
            except TypeError:
                if path.exists():
                    path.unlink()
            return None
        try:
            with open(path, "rb") as f:
                return pickle.load(f)
        except (pickle.UnpicklingError, EOFError):
            return None

    def set(self, key: str, value: Any) -> None:
        path = self._dir / f"{key}.pkl"
        with open(path, "wb") as f:
            pickle.dump(value, f)

    def clear(self) -> int:
        count = 0
        for p in self._dir.glob("*.pkl"):
            p.unlink()
            count += 1
        return count

    def stats(self) -> dict[str, Any]:
        files = list(self._dir.glob("*.pkl"))
        total_size = sum(f.stat().st_size for f in files)
        return {
            "directory": str(self._dir),
            "files": len(files),
            "total_size_bytes": total_size,
            "total_size_human": f"{total_size / 1024:.1f} KB" if total_size > 1024 else f"{total_size} B",
        }
