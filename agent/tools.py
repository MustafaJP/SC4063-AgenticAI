"""
Tool definitions and executor for the agentic forensic investigation.

Each tool wraps an analyzer or data query so the LLM can invoke them dynamically.
"""

import json
from collections import Counter, defaultdict

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
from agent.correlation import correlate_multi_signal_hosts


# ──────────────────────────────────────────────────
# Tool definitions (Ollama tool-calling format)
# ──────────────────────────────────────────────────

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "run_beaconing_analysis",
            "description": (
                "Detect periodic C2 beaconing patterns by analyzing timing intervals "
                "between repeated connections to the same destination. "
                "Use this when you suspect command-and-control activity."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_dns_analysis",
            "description": (
                "Analyze DNS queries for high-entropy domains, DGA patterns, "
                "and potential DNS tunneling. Use this to detect C2 domains "
                "and covert DNS channels."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_http_analysis",
            "description": (
                "Analyze HTTP traffic for suspicious user agents, unusual methods, "
                "long URIs, and potential web-based C2 communication."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_tls_analysis",
            "description": (
                "Analyze TLS sessions for missing SNI, known-bad JA3 fingerprints, "
                "and encrypted communication on non-standard ports."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_ip_reputation",
            "description": (
                "Check all destination IPs against a known-bad IP reputation list. "
                "Detects communication with threat-intelligence-flagged infrastructure."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_smb_analysis",
            "description": (
                "Detect SMB lateral movement: port 445 scanning across internal hosts, "
                "EPM (port 135) service enumeration, and internal data staging via SMB."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_external_access_analysis",
            "description": (
                "Detect external-to-internal access on sensitive ports: "
                "RDP (3389), SSH (22), WinRM, SMB, etc. "
                "Use this to find initial access vectors."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_volumetric_analysis",
            "description": (
                "Detect large outbound data transfers that may indicate exfiltration. "
                "Analyzes session counts and byte volumes from internal to external hosts."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cross_correlation",
            "description": (
                "Correlate findings across multiple signal types to identify hosts "
                "with multiple suspicious behaviors (e.g., beaconing + DNS + exfiltration). "
                "Run this AFTER other analyzers to find multi-signal threats."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_events",
            "description": (
                "Query the event data with filters for deeper investigation. "
                "Use this to drill into specific IPs, ports, protocols, or event types."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "event_type": {
                        "type": "string",
                        "description": "Filter by event type (e.g., 'dns', 'http', 'tls', 'flow')",
                    },
                    "src_ip": {
                        "type": "string",
                        "description": "Filter by source IP address",
                    },
                    "dst_ip": {
                        "type": "string",
                        "description": "Filter by destination IP address",
                    },
                    "dst_port": {
                        "type": "integer",
                        "description": "Filter by destination port",
                    },
                    "keyword": {
                        "type": "string",
                        "description": "Search keyword in event summaries and raw data",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum results to return (default 20)",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finalize_investigation",
            "description": (
                "Call this when you have completed your investigation and are ready "
                "to produce the final report. Provide your reasoning summary."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "reasoning": {
                        "type": "string",
                        "description": "Your final investigative reasoning and key conclusions",
                    },
                },
                "required": ["reasoning"],
            },
        },
    },
]


# ──────────────────────────────────────────────────
# Tool executor
# ──────────────────────────────────────────────────

class ToolExecutor:
    """
    Executes tools called by the LLM during agentic investigation.

    Holds references to the case data and intermediate results so that
    tools can access the events and build up hypotheses progressively.
    """

    def __init__(self, case_data, config, result):
        self.case_data = case_data
        self.config = config
        self.result = result
        self.events = case_data.get("events", [])
        self.finalized = False
        self.final_reasoning = ""

        # Pre-filter event types
        self.dns_events = [e for e in self.events if (e.get("event_type") or "").lower() == "dns"]
        self.http_events = [e for e in self.events if (e.get("event_type") or "").lower() == "http"]
        self.tls_events = [e for e in self.events if (e.get("event_type") or "").lower() == "tls"]

        # Track which tools have been run
        self.tools_run = set()

    def execute(self, tool_name, tool_args):
        """Dispatch a tool call and return the result as a string."""
        self.tools_run.add(tool_name)

        dispatch = {
            "run_beaconing_analysis": self._run_beaconing,
            "run_dns_analysis": self._run_dns,
            "run_http_analysis": self._run_http,
            "run_tls_analysis": self._run_tls,
            "run_ip_reputation": self._run_ip_reputation,
            "run_smb_analysis": self._run_smb,
            "run_external_access_analysis": self._run_external_access,
            "run_volumetric_analysis": self._run_volumetric,
            "run_cross_correlation": self._run_cross_correlation,
            "query_events": self._query_events,
            "finalize_investigation": self._finalize,
        }

        handler = dispatch.get(tool_name)
        if not handler:
            return f"Unknown tool: {tool_name}"

        return handler(tool_args)

    def _format_evidence(self, evidence_list, analyzer_name):
        """Format evidence items into a readable string for the LLM."""
        if not evidence_list:
            return f"{analyzer_name}: No suspicious activity detected."

        lines = [f"{analyzer_name}: Found {len(evidence_list)} suspicious indicator(s)."]
        for ev in evidence_list[:15]:  # Limit to avoid token overflow
            details = ev.details or {}
            lines.append(
                f"  - [{ev.indicator}] {ev.value} "
                f"(score={ev.score:.2f}, entity={details.get('entity', 'N/A')}, "
                f"reasons={details.get('reasons', [])})"
            )
        if len(evidence_list) > 15:
            lines.append(f"  ... and {len(evidence_list) - 15} more.")
        return "\n".join(lines)

    def _run_beaconing(self, args):
        evidence = analyze_beaconing(self.events, self.config)
        from agent.hypothesis_engine import upsert_hypothesis
        for ev in evidence:
            upsert_hypothesis(
                self.result,
                "C2 Beaconing",
                "Repeated periodic communication suggests command-and-control beaconing behavior.",
                "HIGH", ev,
            )
        return self._format_evidence(evidence, "Beaconing Analysis")

    def _run_dns(self, args):
        evidence = analyze_dns(self.dns_events, self.config)
        from agent.hypothesis_engine import upsert_hypothesis
        for ev in evidence:
            upsert_hypothesis(
                self.result,
                "Suspicious DNS Activity",
                "High-entropy or unusually structured DNS queries suggest possible algorithmic domains or DNS-based C2.",
                "MEDIUM", ev,
            )
        return self._format_evidence(evidence, "DNS Analysis")

    def _run_http(self, args):
        evidence = analyze_http(self.http_events, self.config)
        from agent.hypothesis_engine import upsert_hypothesis
        for ev in evidence:
            upsert_hypothesis(
                self.result,
                "Suspicious HTTP C2",
                "Suspicious HTTP behavior suggests possible malware or script-driven communication.",
                "MEDIUM", ev,
            )
        return self._format_evidence(evidence, "HTTP Analysis")

    def _run_tls(self, args):
        evidence = analyze_tls(self.tls_events, self.config)
        from agent.hypothesis_engine import upsert_hypothesis
        for ev in evidence:
            upsert_hypothesis(
                self.result,
                "Suspicious TLS Session",
                "Suspicious TLS metadata suggests encrypted malicious communication.",
                "MEDIUM", ev,
            )
        return self._format_evidence(evidence, "TLS Analysis")

    def _run_ip_reputation(self, args):
        evidence = analyze_bad_ip_reputation(self.events, self.config)
        from agent.hypothesis_engine import upsert_hypothesis
        for ev in evidence:
            upsert_hypothesis(
                self.result,
                "Known Bad IP Communication",
                "Communication with reputation-flagged IP suggests malicious or risky external contact.",
                "HIGH", ev,
            )
        return self._format_evidence(evidence, "IP Reputation Analysis")

    def _run_smb(self, args):
        evidence = analyze_smb(self.events, self.config)
        from agent.hypothesis_engine import upsert_hypothesis
        for ev in evidence:
            upsert_hypothesis(
                self.result,
                "SMB Lateral Movement",
                "Internal SMB scanning or enumeration suggests lateral movement and network reconnaissance.",
                "HIGH", ev,
            )
        return self._format_evidence(evidence, "SMB/Lateral Movement Analysis")

    def _run_external_access(self, args):
        evidence = analyze_external_access(self.events, self.config)
        from agent.hypothesis_engine import upsert_hypothesis
        for ev in evidence:
            upsert_hypothesis(
                self.result,
                "External Sensitive Access",
                "External IP accessed internal host on sensitive port, suggesting unauthorized remote access or initial compromise.",
                "HIGH", ev,
            )
        return self._format_evidence(evidence, "External Access Analysis")

    def _run_volumetric(self, args):
        evidence = analyze_volumetric(self.events, self.config)
        from agent.hypothesis_engine import upsert_hypothesis
        for ev in evidence:
            upsert_hypothesis(
                self.result,
                "Potential Data Exfiltration",
                "Large or frequent outbound transfers to external host suggest data exfiltration.",
                "HIGH", ev,
            )
        return self._format_evidence(evidence, "Volumetric Analysis")

    def _run_cross_correlation(self, args):
        evidence = correlate_multi_signal_hosts(self.result)
        from agent.hypothesis_engine import upsert_hypothesis
        for ev in evidence:
            upsert_hypothesis(
                self.result,
                "Multi-Signal Threat",
                "Multiple suspicious communication patterns from the same host suggest coordinated malicious activity.",
                "HIGH", ev,
            )
        return self._format_evidence(evidence, "Cross-Signal Correlation")

    def _query_events(self, args):
        """Filter and return events for deeper LLM inspection."""
        event_type = args.get("event_type")
        src_ip = args.get("src_ip")
        dst_ip = args.get("dst_ip")
        dst_port = args.get("dst_port")
        keyword = args.get("keyword")
        max_results = args.get("max_results", 20)

        filtered = []
        for e in self.events:
            if event_type and (e.get("event_type") or "").lower() != event_type.lower():
                continue
            if src_ip and e.get("src_ip") != src_ip:
                continue
            if dst_ip and e.get("dst_ip") != dst_ip:
                continue
            if dst_port is not None:
                try:
                    if int(e.get("dst_port", -1)) != int(dst_port):
                        continue
                except (ValueError, TypeError):
                    continue
            if keyword:
                haystack = " ".join([
                    str(e.get("summary") or ""),
                    str(e.get("event_type") or ""),
                    str(e.get("app_proto") or ""),
                    json.dumps(e.get("raw_json") or {}),
                ]).lower()
                if keyword.lower() not in haystack:
                    continue

            filtered.append(e)
            if len(filtered) >= max_results:
                break

        if not filtered:
            return f"No events found matching filters: {args}"

        lines = [f"Found {len(filtered)} event(s) (showing up to {max_results}):"]
        for e in filtered:
            lines.append(
                f"  - [{e.get('event_type', '?')}] "
                f"{e.get('src_ip', '?')}:{e.get('src_port', '?')} -> "
                f"{e.get('dst_ip', '?')}:{e.get('dst_port', '?')} "
                f"proto={e.get('app_proto', '?')} "
                f"ts={e.get('event_timestamp', '?')} "
                f"summary={str(e.get('summary', ''))[:120]}"
            )

        return "\n".join(lines)

    def _finalize(self, args):
        self.finalized = True
        self.final_reasoning = args.get("reasoning", "")
        return "Investigation finalized. Report will be generated."


def build_data_summary(case_data, config):
    """
    Build a concise data summary for the LLM's initial review.

    This gives the LLM enough context to decide which tools to run.
    """
    events = case_data.get("events", [])
    pcaps = case_data.get("pcaps", [])

    event_types = Counter(e.get("event_type", "unknown") for e in events)
    src_ips = Counter(e.get("src_ip") for e in events if e.get("src_ip"))
    dst_ips = Counter(e.get("dst_ip") for e in events if e.get("dst_ip"))
    dst_ports = Counter()
    protocols = Counter(e.get("app_proto") or e.get("network_proto") or "unknown" for e in events)

    for e in events:
        p = e.get("dst_port")
        if p is not None:
            try:
                dst_ports[int(p)] += 1
            except (ValueError, TypeError):
                pass

    # Identify external IPs
    external_src = []
    for ip, count in src_ips.most_common(20):
        if not any(ip.startswith(prefix) for prefix in config.internal_prefixes):
            external_src.append(f"{ip} ({count} events)")

    external_dst = []
    for ip, count in dst_ips.most_common(20):
        if not any(ip.startswith(prefix) for prefix in config.internal_prefixes):
            external_dst.append(f"{ip} ({count} events)")

    # Time range
    timestamps = [e.get("event_timestamp") for e in events if e.get("event_timestamp")]
    time_range = f"{timestamps[0]} to {timestamps[-1]}" if timestamps else "unknown"

    summary = f"""=== CASE DATA SUMMARY ===
Bundle: {case_data.get('bundle_id', 'unknown')}
Total events: {len(events)}
PCAPs: {len(pcaps)}
Time range: {time_range}

Event type distribution:
{chr(10).join(f'  {t}: {c}' for t, c in event_types.most_common(10))}

Top destination ports:
{chr(10).join(f'  port {p}: {c} connections' for p, c in dst_ports.most_common(15))}

Top protocols:
{chr(10).join(f'  {p}: {c}' for p, c in protocols.most_common(10))}

Top internal source IPs:
{chr(10).join(f'  {ip}: {c}' for ip, c in src_ips.most_common(10) if any(ip.startswith(prefix) for prefix in config.internal_prefixes))}

External source IPs (potential attackers):
{chr(10).join(f'  {x}' for x in external_src[:10]) or '  None detected'}

External destination IPs (potential C2/exfil targets):
{chr(10).join(f'  {x}' for x in external_dst[:10]) or '  None detected'}
"""
    return summary
