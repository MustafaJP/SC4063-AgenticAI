from dataclasses import dataclass, field
from typing import Dict, Set, Tuple


@dataclass
class AgentConfig:
    min_confidence_to_report: float = 0.60
    min_confidence_to_escalate: float = 0.75
    min_evidence_items: int = 2
    max_findings: int = 10
    entropy_threshold: float = 3.8
    beacon_min_repeats: int = 4
    beacon_periodicity_threshold: float = 0.75

    # Agentic LLM settings
    ollama_model: str = "llama3.1"
    ollama_url: str = "http://localhost:11434"
    agentic_max_iterations: int = 8
    agentic_enabled: bool = True

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
        "51.91.79.17": 0.95,
    })

    # Allowlisted base domains that should not be flagged by DNS analysis
    allowlisted_domains: Set[str] = field(default_factory=lambda: {
        "microsoft.com",
        "windows.com",
        "windowsupdate.com",
        "azure.com",
        "azure.net",
        "msftconnecttest.com",
        "msedge.net",
        "office.com",
        "office365.com",
        "outlook.com",
        "live.com",
        "trafficmanager.net",
        "cloudapp.azure.com",
        "msftncsi.com",
        "digicert.com",
        "verisign.com",
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "akamai.net",
        "akamaiedge.net",
        "cloudflare.com",
        "amazontrust.com",
        "amazonaws.com",
    })

    # Ports that legitimately use TLS without SNI (not inherently suspicious)
    tls_known_ports: Set[int] = field(default_factory=lambda: {
        3389,   # RDP
        636,    # LDAPS
        993,    # IMAPS
        995,    # POP3S
        5986,   # WinRM HTTPS
        8443,   # Alt HTTPS
    })

    # Internal network prefixes (RFC1918 + common)
    internal_prefixes: Tuple[str, ...] = (
        "10.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.",
        "127.",
    )

    # SMB scanning thresholds
    smb_scan_min_targets: int = 5
    smb_scan_max_interval_ms: float = 500.0

    # Volumetric anomaly thresholds
    volumetric_min_sessions: int = 3
    volumetric_min_bytes: int = 50_000_000  # 50MB