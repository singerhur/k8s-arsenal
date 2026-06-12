"""容器逃逸模块

容器逃逸技术编目与运行时检测。
"""

from k8s_arsenal.escape.vectors import (
    ESCAPE_VECTORS,
    get_escape_vectors_by_capability,
    get_escape_vectors_by_condition,
    get_most_dangerous_vectors,
)
from k8s_arsenal.escape.detector import (
    detect_escape_vectors,
    get_escape_risk_assessment,
)

__all__ = [
    "ESCAPE_VECTORS",
    "detect_escape_vectors",
    "get_escape_risk_assessment",
    "get_escape_vectors_by_capability",
    "get_escape_vectors_by_condition",
    "get_most_dangerous_vectors",
]
