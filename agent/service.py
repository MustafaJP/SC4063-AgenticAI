import time
from agent.config import AgentConfig
from agent.models import InvestigationResult
from agent.mitre import MITRE_MAP
from agent.utils import now_iso
from agent.analyzers import (
    analyze_beaconing,
    analyze_dns,
    analyze_http,
    analyze_tls,
    analyze_bad_ip_reputation,
    analyze_smb,
    analyze_external_access,
    analyze_volumetric,
)
from agent.hypothesis_engine import (
    upsert_hypothesis,
    score_hypotheses,
    apply_guardrails,
)
from agent.correlation import correlate_multi_signal_hosts
from agent.reporter import materialize_findings


class ForensicInvestigationService:
    def __init__(self, config=None):
        self.config = config or AgentConfig()

    def run(self, case_data):
        started = time.perf_counter()

        result = InvestigationResult(
            bundle_id=case_data["bundle_id"],
            summary=case_data.get("summary", {}),
            retrieval_docs=case_data.get("retrieval_docs", []),
            pcaps=case_data.get("pcaps", []),
            events=case_data.get("events", []),
        )

        result.metrics["event_count"] = len(result.events)
        result.metrics["pcap_count"] = len(result.pcaps)

        self._timeline(result, "review_summary", "Started summary-first investigation")

        flows = result.events
        dns_events = [e for e in result.events if (e.get("event_type") or "").lower() == "dns"]
        http_events = [e for e in result.events if (e.get("event_type") or "").lower() == "http"]
        tls_events = [e for e in result.events if (e.get("event_type") or "").lower() == "tls"]

        for ev in analyze_beaconing(flows, self.config):
            upsert_hypothesis(
                result,
                "C2 Beaconing",
                "Repeated periodic communication suggests command-and-control beaconing behavior.",
                "HIGH",
                ev,
            )
        self._timeline(result, "analyze_beaconing", "Completed beaconing analysis")

        for ev in analyze_dns(dns_events, self.config):
            upsert_hypothesis(
                result,
                "Suspicious DNS Activity",
                "High-entropy or unusually structured DNS queries suggest possible algorithmic domains, covert DNS use, or DNS-based command-and-control. Additional corroboration is required before classifying as tunneling.",
                "MEDIUM",
                ev,
            )
        self._timeline(result, "analyze_dns", "Completed DNS analysis")

        for ev in analyze_http(http_events, self.config):
            upsert_hypothesis(
                result,
                "Suspicious HTTP C2",
                "Suspicious HTTP behavior suggests possible malware or script-driven communication.",
                "MEDIUM",
                ev,
            )
        self._timeline(result, "analyze_http", "Completed HTTP analysis")

        for ev in analyze_tls(tls_events, self.config):
            upsert_hypothesis(
                result,
                "Suspicious TLS Session",
                "Suspicious TLS metadata suggests encrypted malicious communication.",
                "MEDIUM",
                ev,
            )
        self._timeline(result, "analyze_tls", "Completed TLS analysis")

        for ev in analyze_bad_ip_reputation(flows, self.config):
            upsert_hypothesis(
                result,
                "Known Bad IP Communication",
                "Communication with reputation-flagged IP suggests malicious or risky external contact.",
                "HIGH",
                ev,
            )
        self._timeline(result, "analyze_bad_ip_reputation", "Completed IP reputation analysis")

        for ev in analyze_smb(flows, self.config):
            upsert_hypothesis(
                result,
                "SMB Lateral Movement",
                "Internal SMB scanning or enumeration suggests lateral movement and network reconnaissance.",
                "HIGH",
                ev,
            )
        self._timeline(result, "analyze_smb", "Completed SMB analysis")

        for ev in analyze_external_access(flows, self.config):
            upsert_hypothesis(
                result,
                "External Sensitive Access",
                "External IP accessed internal host on sensitive port, suggesting unauthorized remote access.",
                "HIGH",
                ev,
            )
        self._timeline(result, "analyze_external_access", "Completed external access analysis")

        for ev in analyze_volumetric(flows, self.config):
            upsert_hypothesis(
                result,
                "Potential Data Exfiltration",
                "Large or frequent outbound transfers to external host suggest data exfiltration.",
                "HIGH",
                ev,
            )
        self._timeline(result, "analyze_volumetric", "Completed volumetric analysis")

        for ev in correlate_multi_signal_hosts(result):
            upsert_hypothesis(
                result,
                "Multi-Signal Threat",
                "Multiple suspicious communication patterns from the same host suggest coordinated malicious activity.",
                "HIGH",
                ev,
            )
        self._timeline(result, "cross_signal_correlation", "Completed cross-signal correlation")

        for hyp in result.hypotheses.values():
            hyp.mitre_techniques = MITRE_MAP.get(hyp.title, [])

        score_hypotheses(result, self.config)
        apply_guardrails(result, self.config)
        materialize_findings(result, self.config)

        self._timeline(result, "materialize_findings", f"Generated {len(result.findings)} final findings")

        elapsed = round(time.perf_counter() - started, 3)
        result.metrics["analysis_runtime_seconds"] = elapsed
        result.metrics["hypothesis_count"] = len(result.hypotheses)
        result.metrics["finding_count"] = len(result.findings)
        result.metrics["estimated_analysis_cost"] = round((elapsed / 3600.0) * 0.05, 4)
        result.metrics["human_review_required_count"] = sum(
            1 for f in result.findings if getattr(f, "human_review_required", False)
        )
        result.metrics["guardrailed_hypothesis_count"] = sum(
            1 for h in result.hypotheses.values() if getattr(h, "guardrail_flags", [])
        )
        result.metrics["finding_with_false_positive_risk_count"] = sum(
            1 for f in result.findings if getattr(f, "false_positive_risks", [])
        )
        result.metrics["finding_with_missed_detection_risk_count"] = sum(
            1 for f in result.findings if getattr(f, "missed_detection_risks", [])
        )

        return result
    
    def _timeline(self, result, step, summary):
        result.timeline.append({
            "timestamp": now_iso(),
            "step": step,
            "summary": summary,
        })
        result.executed_steps.append(step)