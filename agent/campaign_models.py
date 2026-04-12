from dataclasses import dataclass, field
from typing import Dict, List, Set, Any


@dataclass
class CampaignEntity:
    entity_type: str
    value: str
    first_seen: str = ""
    last_seen: str = ""
    bundle_ids: Set[str] = field(default_factory=set)
    source_hosts: Set[str] = field(default_factory=set)
    destination_hosts: Set[str] = field(default_factory=set)
    indicators: Set[str] = field(default_factory=set)
    mitre_techniques: Set[str] = field(default_factory=set)
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    score: float = 0.0


@dataclass
class CampaignFinding:
    title: str
    description: str
    confidence: float
    severity: str
    first_seen: str
    last_seen: str
    bundle_ids: List[str]
    source_hosts: List[str]
    destination_hosts: List[str]
    entities: List[Dict[str, Any]]
    mitre_techniques: List[str]
    recommendation: str
    rationale: List[str]


@dataclass
class CampaignInvestigationResult:
    bundle_results: List[Any] = field(default_factory=list)
    entity_index: Dict[str, CampaignEntity] = field(default_factory=dict)
    campaign_findings: List[CampaignFinding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)