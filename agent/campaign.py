from collections import defaultdict
from datetime import datetime

from agent.campaign_models import (
    CampaignEntity,
    CampaignFinding,
    CampaignInvestigationResult,
)
from agent.service import ForensicInvestigationService


def _parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _update_first_last(entity, ts_value):
    ts = _parse_ts(ts_value)
    if ts is None:
        return

    if not entity.first_seen or ts < _parse_ts(entity.first_seen):
        entity.first_seen = ts.isoformat().replace("+00:00", "Z")
    if not entity.last_seen or ts > _parse_ts(entity.last_seen):
        entity.last_seen = ts.isoformat().replace("+00:00", "Z")


def _entity_key(entity_type, value):
    return f"{entity_type}:{value}"


def _extract_entities_from_result(bundle_result):
    extracted = []

    for hyp in bundle_result.hypotheses.values():
        for ev in hyp.evidence:
            details = ev.details or {}

            src_ip = details.get("src_ip")
            dst_ip = details.get("dst_ip")
            value = str(ev.value)

            if src_ip:
                extracted.append({
                    "entity_type": "src_ip",
                    "value": src_ip,
                    "bundle_id": bundle_result.bundle_id,
                    "timestamp": details.get("event_timestamp") or "",
                    "indicator": ev.indicator,
                    "mitre_techniques": hyp.mitre_techniques,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "score": ev.score,
                })

            if dst_ip:
                extracted.append({
                    "entity_type": "dst_ip",
                    "value": dst_ip,
                    "bundle_id": bundle_result.bundle_id,
                    "timestamp": details.get("event_timestamp") or "",
                    "indicator": ev.indicator,
                    "mitre_techniques": hyp.mitre_techniques,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "score": ev.score,
                })

            if ev.indicator in {"high_entropy_dns", "suspicious_http"}:
                extracted.append({
                    "entity_type": "domain_or_uri",
                    "value": value,
                    "bundle_id": bundle_result.bundle_id,
                    "timestamp": details.get("event_timestamp") or "",
                    "indicator": ev.indicator,
                    "mitre_techniques": hyp.mitre_techniques,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "score": ev.score,
                })

    return extracted


def _score_campaign_entity(entity: CampaignEntity):
    score = 0.0
    rationale = []

    bundle_count = len(entity.bundle_ids)
    source_host_count = len(entity.source_hosts)
    signal_count = len(entity.indicators)
    mitre_count = len(entity.mitre_techniques)

    if bundle_count >= 2:
        score += 0.25
        rationale.append(f"Observed across {bundle_count} bundles")
    if bundle_count >= 4:
        score += 0.15
        rationale.append("Persistence across many bundles")

    if source_host_count >= 2:
        score += 0.20
        rationale.append(f"Observed from {source_host_count} source hosts")

    if signal_count >= 2:
        score += 0.20
        rationale.append(f"Corroborated by {signal_count} different indicators")

    if mitre_count >= 1:
        score += 0.10
        rationale.append("Mapped to MITRE ATT&CK techniques")

    if entity.first_seen and entity.last_seen and entity.first_seen != entity.last_seen:
        score += 0.10
        rationale.append("Observed over an extended time window")

    entity.score = min(1.0, round(score, 3))
    return rationale


def _build_campaign_findings(entity_index):
    findings = []

    for entity in entity_index.values():
        rationale = _score_campaign_entity(entity)

        if entity.score < 0.60:
            continue

        title = "Suspected Long-Running Malicious Infrastructure"
        description = (
            f"The entity `{entity.value}` persisted across multiple bundles and hosts, "
            f"suggesting campaign-level malicious activity rather than an isolated event."
        )

        if "high_entropy_dns" in entity.indicators:
            title = "Suspected Long-Running DNS-Based C2 Activity"
            description = (
                f"The entity `{entity.value}` appeared repeatedly across bundles and hosts with DNS-related "
                f"anomalies, suggesting sustained malicious DNS communication or command-and-control."
            )

        findings.append(
            CampaignFinding(
                title=title,
                description=description,
                confidence=entity.score,
                severity="HIGH" if entity.score >= 0.75 else "MEDIUM",
                first_seen=entity.first_seen,
                last_seen=entity.last_seen,
                bundle_ids=sorted(entity.bundle_ids),
                source_hosts=sorted(entity.source_hosts),
                destination_hosts=sorted(entity.destination_hosts),
                entities=[{
                    "entity_type": entity.entity_type,
                    "value": entity.value,
                }],
                mitre_techniques=sorted(entity.mitre_techniques),
                recommendation=(
                    "Perform retrospective scoping across all affected hosts, block associated infrastructure, "
                    "and validate whether this activity represents sustained intrusion or command-and-control."
                ),
                rationale=rationale,
            )
        )

    findings.sort(key=lambda x: x.confidence, reverse=True)
    return findings


class CampaignInvestigationService:
    def __init__(self, bundle_service=None):
        self.bundle_service = bundle_service or ForensicInvestigationService()

    def run(self, all_case_data):
        result = CampaignInvestigationResult()
        result.metrics["bundle_count"] = len(all_case_data)

        for case_data in all_case_data:
            bundle_result = self.bundle_service.run(case_data)
            result.bundle_results.append(bundle_result)

        entity_index = {}

        for bundle_result in result.bundle_results:
            extracted = _extract_entities_from_result(bundle_result)

            for item in extracted:
                key = _entity_key(item["entity_type"], item["value"])
                if key not in entity_index:
                    entity_index[key] = CampaignEntity(
                        entity_type=item["entity_type"],
                        value=item["value"],
                    )

                entity = entity_index[key]
                entity.bundle_ids.add(item["bundle_id"])

                if item.get("src_ip"):
                    entity.source_hosts.add(item["src_ip"])
                if item.get("dst_ip"):
                    entity.destination_hosts.add(item["dst_ip"])

                entity.indicators.add(item["indicator"])
                for t in item.get("mitre_techniques", []):
                    entity.mitre_techniques.add(t)

                entity.evidence_refs.append(item)
                _update_first_last(entity, item.get("timestamp"))

        result.entity_index = entity_index
        result.campaign_findings = _build_campaign_findings(entity_index)
        result.metrics["campaign_finding_count"] = len(result.campaign_findings)
        result.notes.append("Campaign correlation completed across bundle-level investigation results")

        return result