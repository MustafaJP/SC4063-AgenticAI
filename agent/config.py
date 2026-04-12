from dataclasses import dataclass, field
from typing import Dict, Tuple


@dataclass
class AgentConfig:
    min_confidence_to_report: float = 0.60
    min_confidence_to_escalate: float = 0.75
    min_evidence_items: int = 2
    max_findings: int = 10
    entropy_threshold: float = 3.8
    beacon_min_repeats: int = 4
    beacon_periodicity_threshold: float = 0.75

    suspicious_ua_keywords: Tuple[str, ...] = (
        "python-requests",
        "curl",
        "wget",
        "powershell",
        "go-http-client",
        "libwww-perl",
    )

    known_risky_ja3: Tuple[str, ...] = (
        "72a589da586844d7f0818ce684948eea",
        "e7d705a3286e19ea42f587b344ee6865",
    )

    known_bad_ips: Dict[str, float] = field(default_factory=lambda: {
        "185.220.101.1": 0.90,
        "45.95.147.236": 0.80,
    })