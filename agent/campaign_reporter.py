import json
from pathlib import Path


def build_campaign_json(result):
    return {
        "metrics": result.metrics,
        "notes": result.notes,
        "campaign_findings": [
            {
                "title": finding.title,
                "description": finding.description,
                "confidence": finding.confidence,
                "severity": finding.severity,
                "first_seen": finding.first_seen,
                "last_seen": finding.last_seen,
                "bundle_ids": finding.bundle_ids,
                "source_hosts": finding.source_hosts,
                "destination_hosts": finding.destination_hosts,
                "entities": finding.entities,
                "mitre_techniques": finding.mitre_techniques,
                "recommendation": finding.recommendation,
                "rationale": finding.rationale,
            }
            for finding in result.campaign_findings
        ]
    }


def build_campaign_markdown(result):
    lines = []
    lines.append("# Cross-Bundle Campaign Investigation Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")

    if result.campaign_findings:
        top = result.campaign_findings[0]
        lines.append(
            f"The campaign correlator analyzed **{result.metrics.get('bundle_count', 0)} bundle(s)** "
            f"and identified **{len(result.campaign_findings)} campaign-level finding(s)**. "
            f"The top finding was **{top.title}** with confidence **{top.confidence:.2f}**."
        )
    else:
        lines.append("No cross-bundle campaign-level finding met the reporting threshold.")

    lines.append("")
    lines.append("## Campaign Findings")
    lines.append("")

    if not result.campaign_findings:
        lines.append("No reportable campaign findings.")
    else:
        for idx, finding in enumerate(result.campaign_findings, 1):
            lines.append(f"### {idx}. {finding.title}")
            lines.append(f"- Severity: **{finding.severity}**")
            lines.append(f"- Confidence: **{finding.confidence:.2f}**")
            lines.append(f"- First Seen: {finding.first_seen or 'N/A'}")
            lines.append(f"- Last Seen: {finding.last_seen or 'N/A'}")
            lines.append(f"- Bundles: {', '.join(finding.bundle_ids) or 'N/A'}")
            lines.append(f"- Source Hosts: {', '.join(finding.source_hosts) or 'N/A'}")
            lines.append(f"- Destination Hosts: {', '.join(finding.destination_hosts) or 'N/A'}")
            lines.append(f"- MITRE ATT&CK: {', '.join(finding.mitre_techniques) or 'N/A'}")
            lines.append(f"- Description: {finding.description}")
            lines.append(f"- Recommendation: {finding.recommendation}")
            lines.append("- Rationale:")
            for r in finding.rationale:
                lines.append(f"  - {r}")
            lines.append("")

    return "\n".join(lines)


def write_campaign_reports(result, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)

    with (outdir / "campaign_report.json").open("w", encoding="utf-8") as f:
        json.dump(build_campaign_json(result), f, indent=2)

    with (outdir / "campaign_report.md").open("w", encoding="utf-8") as f:
        f.write(build_campaign_markdown(result))