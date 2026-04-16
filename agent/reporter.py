import json
from pathlib import Path

from agent.models import Finding
from agent.utils import severity_rank


def recommendation_for(title: str) -> str:
    mapping = {
        "C2 Beaconing": "Isolate affected hosts, block destination endpoints, and inspect persistence mechanisms on the source system.",
        "DNS Tunneling": "Block suspicious domains, review DNS logs for affected hosts, and inspect for encoded or covert exfiltration activity.",
        "Suspicious DNS Activity": "Investigate flagged domains, check threat intelligence, and block confirmed malicious domains.",
        "Suspicious HTTP C2": "Block suspicious HTTP destinations and user agents, then inspect endpoints for malware or scripts.",
        "Suspicious TLS Session": "Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.",
        "Known Bad IP Communication": "Block the destination IP immediately and perform retrospective searches across related logs and endpoints.",
        "Possible Data Exfiltration": "Prioritize host isolation, inspect outbound transfer channels, and verify whether sensitive data was accessed or transmitted.",
        "SMB Lateral Movement": "Isolate the scanning host immediately, check for compromised credentials, and audit all accessed systems for signs of compromise.",
        "External Sensitive Access": "Verify authorization of external access, reset credentials on accessed hosts, and review for signs of post-exploitation activity.",
        "Potential Data Exfiltration": "Block the destination IP, isolate the source host, and forensically examine what data may have been transferred.",
        "Multi-Signal Threat": "Treat as high-priority incident — isolate affected host(s), perform full forensic analysis, and coordinate incident response.",
    }
    return mapping.get(title, "Perform additional containment and validation in accordance with incident response procedures.")


def materialize_findings(result, config):
    findings = []
    for hyp in result.hypotheses.values():
        if hyp.confidence < config.min_confidence_to_report:
            continue

        findings.append(
            Finding(
                title=hyp.title,
                description=hyp.description,
                severity=hyp.severity,
                confidence=hyp.confidence,
                mitre_techniques=hyp.mitre_techniques,
                recommendation=recommendation_for(hyp.title),
                affected_entities=hyp.entities,
                evidence=hyp.evidence,
                guardrail_flags=hyp.guardrail_flags,
                human_review_required=hyp.human_review_required,
                false_positive_risks=hyp.false_positive_risks,
                missed_detection_risks=hyp.missed_detection_risks,
                limitations=hyp.limitations,
            )
        )

    findings.sort(key=lambda x: (x.confidence, severity_rank(x.severity)), reverse=True)
    result.findings = findings[: config.max_findings]


def build_json_report(result):
    return {
        "bundle_id": result.bundle_id,
        "metrics": result.metrics,
        "notes": result.notes,
        "safety_controls": result.safety_controls,
        "investigation_limitations": result.investigation_limitations,
        "timeline": result.timeline,
        "executed_steps": result.executed_steps,
        "hypotheses": [
            {
                "hypothesis_id": hyp.hypothesis_id,
                "title": hyp.title,
                "description": hyp.description,
                "severity": hyp.severity,
                "confidence": hyp.confidence,
                "mitre_techniques": hyp.mitre_techniques,
                "entities": hyp.entities,
                "status": hyp.status,
                "guardrail_flags": hyp.guardrail_flags,
                "human_review_required": hyp.human_review_required,
                "false_positive_risks": hyp.false_positive_risks,
                "missed_detection_risks": hyp.missed_detection_risks,
                "limitations": hyp.limitations,
                "evidence": [
                    {
                        "source": ev.source,
                        "indicator": ev.indicator,
                        "value": ev.value,
                        "score": ev.score,
                        "details": ev.details,
                    }
                    for ev in hyp.evidence
                ],
            }
            for hyp in result.hypotheses.values()
        ],
        "findings": [
            {
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "mitre_techniques": finding.mitre_techniques,
                "recommendation": finding.recommendation,
                "affected_entities": finding.affected_entities,
                "guardrail_flags": finding.guardrail_flags,
                "human_review_required": finding.human_review_required,
                "false_positive_risks": finding.false_positive_risks,
                "missed_detection_risks": finding.missed_detection_risks,
                "limitations": finding.limitations,
                "evidence": [
                    {
                        "source": ev.source,
                        "indicator": ev.indicator,
                        "value": ev.value,
                        "score": ev.score,
                        "details": ev.details,
                    }
                    for ev in finding.evidence
                ],
            }
            for finding in result.findings
        ],
    }


def build_markdown_report(result):
    lines = []
    lines.append(f"# Agentic Network Forensic Report — {result.bundle_id}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")

    if result.findings:
        top = result.findings[0]
        lines.append(
            f"The autonomous forensic agent analyzed structured evidence for `{result.bundle_id}` "
            f"and identified **{len(result.findings)} reportable finding(s)**. "
            f"The highest-confidence finding was **{top.title}** with confidence "
            f"**{top.confidence:.2f}** and severity **{top.severity}**."
        )
    else:
        lines.append("No finding met the minimum confidence threshold for formal reporting.")

    lines.append("")
    lines.append("## Analysis Metrics")
    lines.append("")
    lines.append(f"- Event Count: {result.metrics.get('event_count', 0)}")
    lines.append(f"- PCAP Count: {result.metrics.get('pcap_count', 0)}")
    lines.append(f"- Hypothesis Count: {result.metrics.get('hypothesis_count', 0)}")
    lines.append(f"- Finding Count: {result.metrics.get('finding_count', 0)}")
    lines.append(f"- Analysis Runtime (seconds): {result.metrics.get('analysis_runtime_seconds', 0)}")
    lines.append(f"- Estimated Analysis Cost: {result.metrics.get('estimated_analysis_cost', 0)}")
    lines.append(f"- Human Review Required Count: {result.metrics.get('human_review_required_count', 0)}")
    lines.append(f"- Guardrailed Hypothesis Count: {result.metrics.get('guardrailed_hypothesis_count', 0)}")

    lines.append("")
    lines.append("## Safety Controls and Guardrails")
    lines.append("")
    if result.safety_controls:
        for control in result.safety_controls:
            lines.append(f"- **{control.get('control', 'control')}**: {control.get('description', '')}")
    else:
        lines.append("- No explicit safety controls recorded.")

    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not result.findings:
        lines.append("No reportable findings.")
    else:
        for idx, finding in enumerate(result.findings, 1):
            lines.append(f"### {idx}. {finding.title}")
            lines.append(f"- Severity: **{finding.severity}**")
            lines.append(f"- Confidence: **{finding.confidence:.2f}**")
            lines.append(f"- MITRE ATT&CK: {', '.join(finding.mitre_techniques) or 'N/A'}")
            lines.append(f"- Description: {finding.description}")
            lines.append(f"- Recommendation: {finding.recommendation}")
            lines.append(f"- Affected Entities: {', '.join(finding.affected_entities) or 'N/A'}")
            lines.append(f"- Human Review Required: {'Yes' if finding.human_review_required else 'No'}")
            lines.append(f"- Guardrail Flags: {', '.join(finding.guardrail_flags) if finding.guardrail_flags else 'None'}")

            lines.append("- False Positive Risks:")
            if finding.false_positive_risks:
                for item in finding.false_positive_risks:
                    lines.append(f"  - {item}")
            else:
                lines.append("  - None recorded")

            lines.append("- Missed Detection Risks:")
            if finding.missed_detection_risks:
                for item in finding.missed_detection_risks:
                    lines.append(f"  - {item}")
            else:
                lines.append("  - None recorded")

            lines.append("- Technical Limitations:")
            if finding.limitations:
                for item in finding.limitations:
                    lines.append(f"  - {item}")
            else:
                lines.append("  - None recorded")

            lines.append("- Evidence:")
            for ev in finding.evidence:
                lines.append(
                    f"  - [{ev.source}] {ev.indicator} = {ev.value} "
                    f"(score={ev.score:.2f}) details={ev.details}"
                )
            lines.append("")

    lines.append("## Analyst Validation Notes")
    lines.append("")
    review_items = [f for f in result.findings if f.human_review_required]
    if review_items:
        lines.append("The following findings should be validated by a human analyst before containment or attribution decisions:")
        for f in review_items:
            lines.append(f"- {f.title} (confidence={f.confidence:.2f}, flags={', '.join(f.guardrail_flags)})")
    else:
        lines.append("No current findings were specifically flagged for mandatory human review.")

    lines.append("")
    lines.append("## Investigation Limitations")
    lines.append("")
    if result.investigation_limitations:
        for item in result.investigation_limitations:
            lines.append(f"- {item}")
    else:
        lines.append("- No bundle-level limitations recorded.")

    lines.append("")
    lines.append("## False Positives and Missed Detections")
    lines.append("")
    lines.append("- False positives are reduced through minimum evidence thresholds, confidence gating, and human-review flags.")
    lines.append("- Missed detections remain possible where traffic is encrypted, low-volume, disguised as normal behavior, or outside current heuristic coverage.")
    lines.append("- This system is intended to support analyst triage, not replace full forensic validation.")

    lines.append("")
    lines.append("## Investigation Timeline")
    lines.append("")
    for item in result.timeline:
        lines.append(f"- {item['timestamp']} | {item['step']} | {item['summary']}")

    return "\n".join(lines)


def write_investigation_reports(result, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)

    with (outdir / "report.json").open("w", encoding="utf-8") as f:
        json.dump(build_json_report(result), f, indent=2)

    with (outdir / "report.md").open("w", encoding="utf-8") as f:
        f.write(build_markdown_report(result))