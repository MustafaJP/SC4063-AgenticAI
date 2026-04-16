"""
Agentic Forensic Investigation Service.

This replaces the fixed-pipeline approach with an LLM-driven investigation loop:
1. The LLM reviews a data summary and decides what to investigate
2. It calls tools (analyzers, event queries) dynamically
3. It reviews results and decides follow-up actions
4. It iterates until it has enough evidence or hits max iterations
5. It synthesizes a final reasoning narrative

If the LLM (Ollama) is unavailable, falls back to running all analyzers.
"""

import time

from agent.config import AgentConfig
from agent.models import InvestigationResult
from agent.mitre import MITRE_MAP
from agent.utils import now_iso
from agent.hypothesis_engine import score_hypotheses, apply_guardrails
from agent.reporter import materialize_findings
from agent.llm import OllamaClient
from agent.tools import ToolExecutor, TOOL_DEFINITIONS, build_data_summary


SYSTEM_PROMPT = """You are an autonomous network forensic investigator. You have been given
a bundle of network events extracted from PCAP files. Your job is to investigate them for
signs of malicious activity.

You have access to the following investigation tools:
- run_beaconing_analysis: Detect periodic C2 beaconing
- run_dns_analysis: Detect suspicious DNS (DGA, tunneling, C2 domains)
- run_http_analysis: Detect suspicious HTTP traffic (C2, unusual user agents)
- run_tls_analysis: Detect suspicious TLS sessions (missing SNI, bad JA3)
- run_ip_reputation: Check IPs against threat intelligence
- run_smb_analysis: Detect SMB lateral movement and scanning
- run_external_access_analysis: Detect external access to sensitive ports (RDP, SSH)
- run_volumetric_analysis: Detect large outbound data transfers (exfiltration)
- run_cross_correlation: Correlate multiple signals for multi-vector threats
- query_events: Query raw events with filters for deeper investigation
- finalize_investigation: Call when done investigating

INVESTIGATION METHODOLOGY:
1. First, review the data summary to understand what types of traffic are present
2. Start with high-value analyses based on what you see (e.g., if you see port 3389
   traffic from external IPs, run external_access_analysis first)
3. Follow leads — if one analyzer finds something suspicious about an IP, use
   query_events to look at other traffic from that IP
4. Run cross_correlation after you've gathered evidence from multiple analyzers
5. Call finalize_investigation with your reasoning when you're done

Be thorough but efficient. Focus on genuine threats, not benign traffic.
Think about the MITRE ATT&CK framework: Initial Access, Lateral Movement,
Command & Control, Exfiltration, Credential Access.

When you call finalize_investigation, include a detailed reasoning summary covering:
- What you investigated and why
- What you found (with specific IPs, domains, ports)
- Your assessment of the threat level
- Recommended response actions
"""


class AgenticForensicService:
    """
    LLM-driven forensic investigation service.

    The LLM acts as the investigator, choosing which tools to run
    and how to interpret results, making this genuinely agentic.
    """

    def __init__(self, config=None):
        self.config = config or AgentConfig()
        self.llm = OllamaClient(
            model=self.config.ollama_model,
            base_url=self.config.ollama_url,
        )

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

        self._timeline(result, "start", "Started agentic forensic investigation")

        # Build data summary for the LLM
        data_summary = build_data_summary(case_data, self.config)
        self._timeline(result, "data_summary", "Built data summary for LLM review")

        # Create tool executor
        executor = ToolExecutor(case_data, self.config, result)

        # Decide: agentic (LLM-driven) or fallback (rule-based)
        if self.config.agentic_enabled and self.llm.is_available():
            self._run_agentic(result, executor, data_summary)
        else:
            reason = "LLM unavailable" if not self.llm.is_available() else "agentic mode disabled"
            self._timeline(result, "fallback", f"Using fallback mode ({reason})")
            self._run_fallback(result, executor, data_summary)

        # Post-processing: scoring, guardrails, findings
        for hyp in result.hypotheses.values():
            hyp.mitre_techniques = MITRE_MAP.get(hyp.title, [])

        score_hypotheses(result, self.config)
        apply_guardrails(result, self.config)
        materialize_findings(result, self.config)

        self._timeline(result, "materialize_findings",
                       f"Generated {len(result.findings)} final findings")

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
        result.metrics["tools_invoked"] = sorted(executor.tools_run)
        result.metrics["agentic_mode"] = self.config.agentic_enabled and self.llm.is_available()

        return result

    def _run_agentic(self, result, executor, data_summary):
        """
        LLM-driven investigation loop.

        The LLM reads the data summary, chooses tools, reviews results,
        and iterates until it calls finalize_investigation.
        """
        self._timeline(result, "agentic_start", "Starting LLM-driven investigation")

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Please investigate the following network forensic case.\n\n"
                    f"{data_summary}\n\n"
                    f"Begin your investigation by choosing which tools to run based on "
                    f"what you observe in the data summary. Call your tools one at a time."
                ),
            },
        ]

        final_content, conversation, tool_trace = self.llm.chat_with_tools(
            messages=messages,
            tools=TOOL_DEFINITIONS,
            tool_executor=executor.execute,
            max_rounds=self.config.agentic_max_iterations,
        )

        # Log the investigation trace
        for entry in tool_trace:
            self._timeline(
                result,
                f"tool_{entry['tool']}",
                f"LLM invoked {entry['tool']} (round {entry['round']})"
            )

        # Store the LLM's reasoning
        result.notes.append(f"LLM Investigation Reasoning:\n{final_content}")
        result.metrics["llm_tool_trace"] = tool_trace
        result.metrics["llm_rounds"] = len(tool_trace)
        result.metrics["llm_final_reasoning"] = final_content

        if executor.final_reasoning:
            result.notes.append(f"LLM Final Summary:\n{executor.final_reasoning}")

        self._timeline(result, "agentic_complete",
                       f"LLM investigation complete ({len(tool_trace)} tool calls)")

    def _run_fallback(self, result, executor, data_summary):
        """
        Fallback: run all analyzers in sequence (improved version of original pipeline).

        This runs when Ollama is unavailable but still uses the new analyzers.
        """
        tool_sequence = [
            "run_external_access_analysis",
            "run_beaconing_analysis",
            "run_dns_analysis",
            "run_http_analysis",
            "run_tls_analysis",
            "run_ip_reputation",
            "run_smb_analysis",
            "run_volumetric_analysis",
            "run_cross_correlation",
        ]

        for tool_name in tool_sequence:
            try:
                executor.execute(tool_name, {})
                self._timeline(result, tool_name, f"Completed {tool_name}")
            except Exception as e:
                self._timeline(result, tool_name, f"Error in {tool_name}: {e}")

        result.notes.append(
            "Investigation ran in fallback mode (all analyzers executed sequentially). "
            "For LLM-driven agentic investigation, ensure Ollama is running."
        )

    def _timeline(self, result, step, summary):
        result.timeline.append({
            "timestamp": now_iso(),
            "step": step,
            "summary": summary,
        })
        result.executed_steps.append(step)
