import argparse
import json
import re
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def find_bundle_reports(agent_outdir: Path) -> List[Path]:
    reports = []

    if not agent_outdir.exists():
        return reports

    for child in sorted(agent_outdir.iterdir()):
        if not child.is_dir():
            continue
        if child.name in {"campaign", "master"}:
            continue

        report_path = child / "report.json"
        if report_path.exists():
            reports.append(report_path)

    return reports


def load_bundle_reports(agent_outdir: Path) -> List[Dict[str, Any]]:
    reports = []
    for path in find_bundle_reports(agent_outdir):
        data = load_json(path)
        data["_source_path"] = str(path)
        reports.append(data)
    return reports


def load_campaign_report(agent_outdir: Path) -> Dict[str, Any]:
    campaign_path = agent_outdir / "campaign" / "campaign_report.json"
    if not campaign_path.exists():
        return {}

    data = load_json(campaign_path)
    data["_source_path"] = str(campaign_path)
    return data


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def parse_evidence_timestamp(ts_str: str) -> str:
    """Convert evidence timestamp to ISO 8601. Returns '' on failure."""
    if not ts_str:
        return ""
    ts_str = ts_str.strip()
    # Already ISO-like (starts with 4-digit year)
    if re.match(r'^\d{4}-\d{2}-\d{2}', ts_str):
        return ts_str
    # "Nov 18, 2025 21:30:11.906844000 +08" – strip sub-microsecond, pad tz
    m = re.match(
        r'(\w{3})\s+(\d{1,2}),\s+(\d{4})\s+(\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+([+-]\d{2})$',
        ts_str,
    )
    if m:
        mon, day, year, time_part, tz = m.groups()
        tz_padded = tz + "00"  # "+08" → "+0800"
        try:
            dt = datetime.strptime(
                f"{mon} {day} {year} {time_part} {tz_padded}",
                "%b %d %Y %H:%M:%S %z",
            )
            return dt.isoformat()
        except ValueError:
            pass
    return ""


def build_hypothesis_timeline(bundle_reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return one timeline entry per hypothesis, timestamped from actual network events."""
    events: List[Dict[str, Any]] = []

    for report in bundle_reports:
        bundle_id = report.get("bundle_id", "unknown")

        # Fallback date extracted from bundle_id like "bundle_2025-11-18_…"
        bundle_date_iso = ""
        bd_match = re.search(r"(\d{4}-\d{2}-\d{2})", bundle_id)
        if bd_match:
            bundle_date_iso = bd_match.group(1) + "T00:00:00+00:00"

        for hyp in report.get("hypotheses", []):
            evidence_list = hyp.get("evidence", []) or []

            # Earliest real network timestamp from evidence details
            event_ts = ""
            for ev in evidence_list:
                details = ev.get("details", {}) or {}
                raw = normalize_text(details.get("event_timestamp", ""))
                if raw:
                    parsed = parse_evidence_timestamp(raw)
                    if parsed and (not event_ts or parsed < event_ts):
                        event_ts = parsed

            if not event_ts:
                event_ts = bundle_date_iso

            # Condensed evidence context (what the analyzer saw + where)
            ev_context = []
            for ev in evidence_list[:8]:
                details = ev.get("details", {}) or {}
                ctx: Dict[str, Any] = {
                    "source": normalize_text(ev.get("source", "")),
                    "indicator": normalize_text(ev.get("indicator", "")),
                    "value": normalize_text(ev.get("value", "")),
                    "score": safe_float(ev.get("score", 0)),
                }
                for field in ("src_ip", "dst_ip", "dst_port", "service",
                              "reasons", "connection_count"):
                    val = details.get(field)
                    if val is not None:
                        ctx[field] = val
                ev_context.append(ctx)

            events.append({
                "bundle_id": bundle_id,
                "hypothesis_id": normalize_text(hyp.get("hypothesis_id", "")),
                "title": normalize_text(hyp.get("title", "")) or "Unknown",
                "description": normalize_text(hyp.get("description", "")),
                "severity": normalize_text(hyp.get("severity", "")) or "UNKNOWN",
                "confidence": safe_float(hyp.get("confidence", 0.0)),
                "event_timestamp": event_ts,
                "entities": [
                    normalize_text(e)
                    for e in (hyp.get("entities") or [])
                    if normalize_text(e)
                ],
                "mitre_techniques": sorted({
                    normalize_text(t)
                    for t in (hyp.get("mitre_techniques") or [])
                    if normalize_text(t)
                }),
                "guardrail_flags": hyp.get("guardrail_flags") or [],
                "human_review_required": bool(hyp.get("human_review_required", False)),
                "false_positive_risks": hyp.get("false_positive_risks") or [],
                "limitations": hyp.get("limitations") or [],
                "is_finding": safe_float(hyp.get("confidence", 0.0)) >= 0.6,
                "evidence_context": ev_context,
            })

    events.sort(key=lambda x: x.get("event_timestamp") or "")
    return events


def aggregate_master_data(
    bundle_reports: List[Dict[str, Any]],
    campaign_report: Dict[str, Any]
) -> Dict[str, Any]:
    severity_counter = Counter()
    mitre_counter = Counter()
    title_counter = Counter()
    affected_entities = Counter()
    source_host_counter = Counter()
    destination_host_counter = Counter()

    bundle_findings = []
    all_findings = []

    first_seen = None
    last_seen = None
    human_review_required_count = 0

    for report in bundle_reports:
        bundle_id = report.get("bundle_id", "unknown_bundle")
        findings = report.get("findings", [])
        metrics = report.get("metrics", {})

        top_finding_title = None
        top_confidence = None
        if findings:
            sorted_findings = sorted(
                findings,
                key=lambda x: safe_float(x.get("confidence", 0.0)),
                reverse=True
            )
            top_finding_title = sorted_findings[0].get("title")
            top_confidence = sorted_findings[0].get("confidence")

        bundle_findings.append({
            "bundle_id": bundle_id,
            "finding_count": len(findings),
            "event_count": metrics.get("event_count", 0),
            "pcap_count": metrics.get("pcap_count", 0),
            "hypothesis_count": metrics.get("hypothesis_count", 0),
            "top_finding": top_finding_title,
            "top_confidence": top_confidence,
        })

        for finding in findings:
            title = normalize_text(finding.get("title")) or "Unknown"
            severity = normalize_text(finding.get("severity")) or "UNKNOWN"
            confidence = safe_float(finding.get("confidence", 0.0))
            mitre = finding.get("mitre_techniques", []) or []
            entities = finding.get("affected_entities", []) or []
            recommendation = normalize_text(finding.get("recommendation"))
            human_review_required = bool(finding.get("human_review_required", False))
            guardrail_flags = finding.get("guardrail_flags", []) or []
            evidence = finding.get("evidence", []) or []

            if human_review_required:
                human_review_required_count += 1

            title_counter[title] += 1
            severity_counter[severity] += 1

            cleaned_entities = []
            for entity in entities:
                entity_text = normalize_text(entity)
                if entity_text:
                    affected_entities[entity_text] += 1
                    cleaned_entities.append(entity_text)

            finding_source_hosts = set()
            finding_destination_hosts = set()

            for ev in evidence:
                details = ev.get("details", {}) or {}
                src_ip = normalize_text(details.get("src_ip"))
                dst_ip = normalize_text(details.get("dst_ip"))

                if src_ip:
                    source_host_counter[src_ip] += 1
                    finding_source_hosts.add(src_ip)

                if dst_ip:
                    destination_host_counter[dst_ip] += 1
                    finding_destination_hosts.add(dst_ip)

            for t in mitre:
                t_text = normalize_text(t)
                if t_text:
                    mitre_counter[t_text] += 1

            all_findings.append({
                "bundle_id": bundle_id,
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "mitre_techniques": sorted({normalize_text(x) for x in mitre if normalize_text(x)}),
                "affected_entities": sorted(set(cleaned_entities)),
                "source_hosts": sorted(finding_source_hosts),
                "destination_hosts": sorted(finding_destination_hosts),
                "recommendation": recommendation,
                "human_review_required": human_review_required,
                "guardrail_flags": guardrail_flags,
            })

        timeline = report.get("timeline", [])
        for item in timeline:
            ts = item.get("timestamp")
            if not ts:
                continue
            if first_seen is None or str(ts) < str(first_seen):
                first_seen = ts
            if last_seen is None or str(ts) > str(last_seen):
                last_seen = ts

    all_findings.sort(
        key=lambda x: (x["confidence"], x["severity"], x["title"]),
        reverse=True
    )

    top_entities = [
        {"entity": entity, "count": count}
        for entity, count in affected_entities.most_common(15)
    ]

    top_titles = [
        {"title": title, "count": count}
        for title, count in title_counter.most_common(10)
    ]

    top_mitre = [
        {"technique": technique, "count": count}
        for technique, count in mitre_counter.most_common(10)
    ]

    top_source_hosts = [
        {"host": host, "count": count}
        for host, count in source_host_counter.most_common(10)
    ]

    top_destination_hosts = [
        {"host": host, "count": count}
        for host, count in destination_host_counter.most_common(10)
    ]

    campaign_findings = campaign_report.get("campaign_findings", []) if campaign_report else []

    return {
        "generated_at": utc_now_iso(),
        "bundle_count": len(bundle_reports),
        "campaign_finding_count": len(campaign_findings),
        "total_bundle_findings": len(all_findings),
        "human_review_required_count": human_review_required_count,
        "severity_distribution": dict(severity_counter),
        "top_finding_titles": top_titles,
        "top_mitre_techniques": top_mitre,
        "top_entities": top_entities,
        "top_source_hosts": top_source_hosts,
        "top_destination_hosts": top_destination_hosts,
        "bundle_summaries": bundle_findings,
        "top_findings": all_findings[:20],
        "campaign_report": campaign_report,
        "investigation_window": {
            "first_seen": first_seen,
            "last_seen": last_seen,
        },
        "hypothesis_timeline": build_hypothesis_timeline(bundle_reports),
    }


def call_ollama_summary(master_data: Dict[str, Any], model: str) -> Optional[str]:
    prompt = (
        "You are a SOC report writer. Write a concise executive summary for a master "
        "network forensics report. Focus on recurring patterns, campaign-level signals, "
        "top risks, affected entities, and analyst actions. Keep it professional and do not invent facts.\n\n"
        f"DATA:\n{json.dumps(master_data, ensure_ascii=False)[:20000]}"
    )

    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False
    }).encode("utf-8")

    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return body.get("response", "").strip() or None
    except Exception:
        return None


def build_default_executive_summary(master_data: Dict[str, Any]) -> str:
    bundle_count = master_data.get("bundle_count", 0)
    total_findings = master_data.get("total_bundle_findings", 0)
    campaign_finding_count = master_data.get("campaign_finding_count", 0)

    top_titles = master_data.get("top_finding_titles", [])
    top_entities = master_data.get("top_entities", [])
    top_sources = master_data.get("top_source_hosts", [])

    title_text = ", ".join(x["title"] for x in top_titles[:3]) if top_titles else "no dominant finding category"
    entity_text = ", ".join(x["entity"] for x in top_entities[:5]) if top_entities else "no dominant affected entities"
    source_text = ", ".join(x["host"] for x in top_sources[:5]) if top_sources else "no dominant source hosts"

    if campaign_finding_count:
        campaign_text = (
            f"Cross-bundle correlation identified {campaign_finding_count} campaign-level finding(s), "
            f"indicating persistence beyond a single bundle."
        )
    else:
        campaign_text = "Cross-bundle correlation did not produce any reportable campaign-level findings."

    return (
        f"The master synthesizer reviewed {bundle_count} bundle-level reports and consolidated "
        f"{total_findings} reportable findings. The most recurrent finding categories were {title_text}. "
        f"The most frequently affected entities included {entity_text}, and the most recurrent source hosts included {source_text}. "
        f"{campaign_text}"
    )


def build_findings_flowchart(master_data: Dict[str, Any]) -> str:
    lines = ["flowchart TD"]

    lines.append('    A[All Bundle Reports]')
    lines.append('    Z[Campaign Report]')

    finding_to_entities = defaultdict(set)
    finding_to_source_hosts = defaultdict(set)
    finding_to_destination_hosts = defaultdict(set)
    entity_counter = Counter()
    finding_counter = Counter()

    for finding in master_data.get("top_findings", []):
        title = normalize_text(finding.get("title")) or "Unknown Finding"
        finding_counter[title] += 1

        for entity in finding.get("affected_entities", []):
            entity_text = normalize_text(entity)
            if entity_text:
                finding_to_entities[title].add(entity_text)
                entity_counter[entity_text] += 1

        for src in finding.get("source_hosts", []):
            src_text = normalize_text(src)
            if src_text:
                label = f"Source {src_text}"
                finding_to_source_hosts[title].add(label)
                entity_counter[label] += 1

        for dst in finding.get("destination_hosts", []):
            dst_text = normalize_text(dst)
            if dst_text:
                label = f"Destination {dst_text}"
                finding_to_destination_hosts[title].add(label)
                entity_counter[label] += 1

    campaign_findings = master_data.get("campaign_report", {}).get("campaign_findings", []) or []

    finding_ids = {}
    for idx, (title, count) in enumerate(finding_counter.items(), 1):
        f_id = f"F{idx}"
        finding_ids[title] = f_id
        safe_title = title.replace('"', "'")
        lines.append(f'    A --> {f_id}["{safe_title} ({count})"]')

    entity_node_map = {}
    e_idx = 1

    def ensure_entity_node(label: str) -> str:
        nonlocal e_idx
        if label not in entity_node_map:
            entity_node_map[label] = f"E{e_idx}"
            safe_label = label.replace('"', "'")
            lines.append(f'    {entity_node_map[label]}["{safe_label}"]')
            e_idx += 1
        return entity_node_map[label]

    for title, entities in finding_to_entities.items():
        for entity in sorted(entities)[:8]:
            entity_id = ensure_entity_node(entity)
            lines.append(f"    {finding_ids[title]} --> {entity_id}")

    for title, src_hosts in finding_to_source_hosts.items():
        for src_label in sorted(src_hosts)[:5]:
            src_id = ensure_entity_node(src_label)
            lines.append(f"    {finding_ids[title]} --> {src_id}")

    for title, dst_hosts in finding_to_destination_hosts.items():
        for dst_label in sorted(dst_hosts)[:5]:
            dst_id = ensure_entity_node(dst_label)
            lines.append(f"    {finding_ids[title]} --> {dst_id}")

    repeated_entities = [e for e, c in entity_counter.items() if c >= 2]
    if repeated_entities:
        lines.append('    R1[Repeated Entities Across Findings]')
        for entity in repeated_entities[:10]:
            entity_id = ensure_entity_node(entity)
            lines.append(f"    {entity_id} --> R1")

    if campaign_findings:
        for idx, cf in enumerate(campaign_findings, 1):
            c_id = f"C{idx}"
            title = normalize_text(cf.get("title")) or f"Campaign Finding {idx}"
            title = title.replace('"', "'")
            lines.append(f'    Z --> {c_id}["{title}"]')

            for src in cf.get("source_hosts", [])[:5]:
                src_label = f"Source {normalize_text(src)}"
                if normalize_text(src):
                    src_id = ensure_entity_node(src_label)
                    lines.append(f"    {src_id} --> {c_id}")

            for dst in cf.get("destination_hosts", [])[:5]:
                dst_label = f"Destination {normalize_text(dst)}"
                if normalize_text(dst):
                    dst_id = ensure_entity_node(dst_label)
                    lines.append(f"    {dst_id} --> {c_id}")

            for entity in cf.get("entities", [])[:5]:
                if isinstance(entity, dict):
                    entity_value = normalize_text(entity.get("value"))
                else:
                    entity_value = normalize_text(entity)

                if entity_value:
                    entity_id = ensure_entity_node(entity_value)
                    lines.append(f"    {entity_id} --> {c_id}")

    lines.append('    X1[Cross-Signal Correlation]')
    lines.append('    X2[Likely Sustained Malicious Activity]')
    lines.append('    X3[Containment / Blocking / Retrospective Scoping]')

    if repeated_entities:
        lines.append("    R1 --> X1")

    for idx, _ in enumerate(campaign_findings, 1):
        lines.append(f"    C{idx} --> X2")

    important_titles = {
        "Suspicious DNS Activity",
        "Suspicious HTTP C2",
        "Suspicious TLS Session",
        "Known Bad IP Communication",
        "C2 Beaconing",
        "Possible Data Exfiltration",
    }

    for title, f_id in finding_ids.items():
        if title in important_titles:
            lines.append(f"    {f_id} --> X1")

    lines.append("    X1 --> X2")
    lines.append("    X2 --> X3")

    return "\n".join(lines)


def build_master_markdown(
    master_data: Dict[str, Any],
    executive_summary: str,
    findings_flowchart: str
) -> str:
    lines = []
    lines.append("# Master Network Forensics Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(executive_summary)
    lines.append("")

    window = master_data.get("investigation_window", {})
    lines.append("## Scope")
    lines.append("")
    lines.append(f"- Bundles analyzed: {master_data.get('bundle_count', 0)}")
    lines.append(f"- Total reportable bundle findings: {master_data.get('total_bundle_findings', 0)}")
    lines.append(f"- Campaign-level findings: {master_data.get('campaign_finding_count', 0)}")
    lines.append(f"- Human review required count: {master_data.get('human_review_required_count', 0)}")
    lines.append(f"- First observed timeline event: {window.get('first_seen') or 'N/A'}")
    lines.append(f"- Last observed timeline event: {window.get('last_seen') or 'N/A'}")
    lines.append("")

    lines.append("## Recurrent Finding Categories")
    lines.append("")
    for item in master_data.get("top_finding_titles", []):
        lines.append(f"- {item['title']}: {item['count']}")
    if not master_data.get("top_finding_titles"):
        lines.append("- None")
    lines.append("")

    lines.append("## Most Frequent MITRE ATT&CK Techniques")
    lines.append("")
    for item in master_data.get("top_mitre_techniques", []):
        lines.append(f"- {item['technique']}: {item['count']}")
    if not master_data.get("top_mitre_techniques"):
        lines.append("- None")
    lines.append("")

    lines.append("## Most Frequent Source Hosts")
    lines.append("")
    for item in master_data.get("top_source_hosts", []):
        lines.append(f"- {item['host']}: {item['count']}")
    if not master_data.get("top_source_hosts"):
        lines.append("- None")
    lines.append("")

    lines.append("## Most Frequent Destination Hosts")
    lines.append("")
    for item in master_data.get("top_destination_hosts", []):
        lines.append(f"- {item['host']}: {item['count']}")
    if not master_data.get("top_destination_hosts"):
        lines.append("- None")
    lines.append("")

    lines.append("## Most Frequently Affected Entities")
    lines.append("")
    for item in master_data.get("top_entities", []):
        lines.append(f"- {item['entity']}: {item['count']}")
    if not master_data.get("top_entities"):
        lines.append("- None")
    lines.append("")

    lines.append("## Bundle-by-Bundle Summary")
    lines.append("")
    for item in master_data.get("bundle_summaries", []):
        lines.append(
            f"- {item['bundle_id']}: findings={item['finding_count']}, "
            f"events={item['event_count']}, pcaps={item['pcap_count']}, "
            f"top_finding={item['top_finding'] or 'None'}, "
            f"top_confidence={item['top_confidence'] if item['top_confidence'] is not None else 'N/A'}"
        )
    if not master_data.get("bundle_summaries"):
        lines.append("- None")
    lines.append("")

    lines.append("## Top Findings Across All Bundles")
    lines.append("")
    for idx, item in enumerate(master_data.get("top_findings", []), 1):
        lines.append(f"### {idx}. {item['title']}")
        lines.append(f"- Bundle: {item['bundle_id']}")
        lines.append(f"- Severity: {item['severity']}")
        lines.append(f"- Confidence: {item['confidence']:.2f}")
        lines.append(f"- MITRE ATT&CK: {', '.join(item['mitre_techniques']) or 'N/A'}")
        lines.append(f"- Source Hosts: {', '.join(item['source_hosts']) or 'N/A'}")
        lines.append(f"- Destination Hosts: {', '.join(item['destination_hosts']) or 'N/A'}")
        lines.append(f"- Affected Entities: {', '.join(item['affected_entities']) or 'N/A'}")
        lines.append(f"- Recommendation: {item['recommendation'] or 'N/A'}")
        lines.append(f"- Human Review Required: {'Yes' if item['human_review_required'] else 'No'}")
        lines.append(f"- Guardrail Flags: {', '.join(item['guardrail_flags']) if item['guardrail_flags'] else 'None'}")
        lines.append("")

    campaign_findings = master_data.get("campaign_report", {}).get("campaign_findings", [])
    lines.append("## Campaign-Level Correlation")
    lines.append("")
    if campaign_findings:
        for idx, finding in enumerate(campaign_findings, 1):
            lines.append(f"### {idx}. {finding.get('title', 'Campaign Finding')}")
            lines.append(f"- Severity: {finding.get('severity', 'N/A')}")
            lines.append(f"- Confidence: {safe_float(finding.get('confidence', 0.0)):.2f}")
            lines.append(f"- First Seen: {finding.get('first_seen', 'N/A')}")
            lines.append(f"- Last Seen: {finding.get('last_seen', 'N/A')}")
            lines.append(f"- Bundles: {', '.join(finding.get('bundle_ids', [])) or 'N/A'}")
            lines.append(f"- Source Hosts: {', '.join(finding.get('source_hosts', [])) or 'N/A'}")
            lines.append(f"- Destination Hosts: {', '.join(finding.get('destination_hosts', [])) or 'N/A'}")
            lines.append(f"- MITRE ATT&CK: {', '.join(finding.get('mitre_techniques', [])) or 'N/A'}")
            lines.append(f"- Description: {finding.get('description', 'N/A')}")
            lines.append(f"- Recommendation: {finding.get('recommendation', 'N/A')}")

            rationale = finding.get("rationale", []) or []
            if rationale:
                lines.append("- Rationale:")
                for item in rationale:
                    lines.append(f"  - {item}")
            lines.append("")
    else:
        lines.append("No campaign-level finding met the reporting threshold.")
        lines.append("")

    lines.append("## Findings Flowchart")
    lines.append("")
    lines.append("The following diagram summarizes how repeated findings connect to affected entities, recurring hosts, campaign correlation, and final analyst actions.")
    lines.append("")
    lines.append("```mermaid")
    lines.append(findings_flowchart)
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


def write_outputs(outdir: Path, master_data: Dict[str, Any], markdown: str, flowchart: str) -> None:
    outdir.mkdir(parents=True, exist_ok=True)

    with (outdir / "master_report.json").open("w", encoding="utf-8") as f:
        json.dump(master_data, f, indent=2)

    with (outdir / "master_report.md").open("w", encoding="utf-8") as f:
        f.write(markdown)

    with (outdir / "findings_flowchart.mmd").open("w", encoding="utf-8") as f:
        f.write(flowchart)


def main(agent_outdir: str, master_subdir: str, ollama_model: str = "", use_llm: bool = False) -> None:
    agent_outdir_path = Path(agent_outdir)
    outdir = agent_outdir_path / master_subdir

    bundle_reports = load_bundle_reports(agent_outdir_path)
    campaign_report = load_campaign_report(agent_outdir_path)

    master_data = aggregate_master_data(bundle_reports, campaign_report)

    llm_summary = None
    if use_llm and ollama_model:
        llm_summary = call_ollama_summary(master_data, ollama_model)

    executive_summary = llm_summary or build_default_executive_summary(master_data)
    master_data["executive_summary"] = executive_summary

    flowchart = build_findings_flowchart(master_data)
    markdown = build_master_markdown(master_data, executive_summary, flowchart)

    write_outputs(outdir, master_data, markdown, flowchart)

    print(json.dumps({
        "status": "ok",
        "bundle_reports_loaded": len(bundle_reports),
        "campaign_report_loaded": bool(campaign_report),
        "outdir": str(outdir),
        "used_llm_summary": bool(llm_summary),
    }, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Synthesize scattered forensic reports into one master report with a findings flowchart."
    )
    parser.add_argument("--agent-outdir", default="agent_outputs")
    parser.add_argument("--master-subdir", default="master")
    parser.add_argument("--use-llm", action="store_true")
    parser.add_argument("--ollama-model", default="")

    args = parser.parse_args()

    main(
        agent_outdir=args.agent_outdir,
        master_subdir=args.master_subdir,
        ollama_model=args.ollama_model,
        use_llm=args.use_llm,
    )