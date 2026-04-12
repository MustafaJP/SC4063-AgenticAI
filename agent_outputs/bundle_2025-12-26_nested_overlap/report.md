# Agentic Network Forensic Report — bundle_2025-12-26_nested_overlap

## Executive Summary

No finding met the minimum confidence threshold for formal reporting.

## Analysis Metrics

- Event Count: 36
- PCAP Count: 1
- Hypothesis Count: 0
- Finding Count: 0
- Analysis Runtime (seconds): 0.0
- Estimated Analysis Cost: 0.0
- Human Review Required Count: 0
- Guardrailed Hypothesis Count: 0

## Safety Controls and Guardrails

- **minimum_evidence_requirement**: Hypotheses with fewer than 2 evidence items are downgraded below formal reporting threshold.
- **confidence_threshold_for_reporting**: Only hypotheses with confidence >= 0.6 are materialized as findings.
- **human_review_for_high_impact_or_thin_claims**: Potentially high-impact findings and thinly corroborated claims are flagged for analyst validation before operational use.
- **source_diversity_tracking**: Hypotheses record whether evidence came from limited or multiple analytic sources.

## Findings

No reportable findings.
## Analyst Validation Notes

No current findings were specifically flagged for mandatory human review.

## Investigation Limitations

- This investigation uses network-derived evidence only and has no host-level telemetry.
- Some detections rely on protocol metadata and heuristics rather than full semantic reconstruction.
- Encrypted traffic may reduce visibility into true intent or content.
- Threshold-based logic can reduce false positives but may also reduce recall.

## False Positives and Missed Detections

- False positives are reduced through minimum evidence thresholds, confidence gating, and human-review flags.
- Missed detections remain possible where traffic is encrypted, low-volume, disguised as normal behavior, or outside current heuristic coverage.
- This system is intended to support analyst triage, not replace full forensic validation.

## Investigation Timeline

- 2026-04-12T14:54:41.073472Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:41.073546Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:41.073554Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:41.073556Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:41.073558Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:41.073563Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:41.073565Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:41.073571Z | materialize_findings | Generated 0 final findings