import math
from collections import Counter
from datetime import datetime


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def severity_rank(severity: str) -> int:
    return {
        "INFO": 1,
        "LOW": 2,
        "MEDIUM": 3,
        "HIGH": 4,
        "CRITICAL": 5,
    }.get(severity, 0)