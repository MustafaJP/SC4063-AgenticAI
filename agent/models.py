from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Evidence:
    source: str
    indicator: str
    value: Any
    score: float
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Hypothesis:
    hypothesis_id: str
    title: str
    description: str
    severity: str
    confidence: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    entities: List[str] = field(default_factory=list)
    status: str = "OPEN"
    guardrail_flags: List[str] = field(default_factory=list)
    human_review_required: bool = False
    false_positive_risks: List[str] = field(default_factory=list)
    missed_detection_risks: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Finding:
    title: str
    description: str
    severity: str
    confidence: float
    mitre_techniques: List[str]
    recommendation: str
    affected_entities: List[str]
    evidence: List[Evidence]
    guardrail_flags: List[str] = field(default_factory=list)
    human_review_required: bool = False
    false_positive_risks: List[str] = field(default_factory=list)
    missed_detection_risks: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class InvestigationResult:
    bundle_id: str
    summary: Dict
    retrieval_docs: List[Dict]
    pcaps: List[Dict]
    events: List[Dict]
    notes: List[str] = field(default_factory=list)
    hypotheses: Dict[str, Hypothesis] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    executed_steps: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    safety_controls: List[Dict[str, Any]] = field(default_factory=list)
    investigation_limitations: List[str] = field(default_factory=list)