# Agentic Network Forensic Report — bundle_2025-12-04_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2025-12-04_nested_overlap` and identified **1 reportable finding(s)**. The highest-confidence finding was **Suspicious TLS Session** with confidence **0.79** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 147
- PCAP Count: 4
- Hypothesis Count: 2
- Finding Count: 1
- Analysis Runtime (seconds): 0.001
- Estimated Analysis Cost: 0.0
- Human Review Required Count: 0
- Guardrailed Hypothesis Count: 2

## Safety Controls and Guardrails

- **minimum_evidence_requirement**: Hypotheses with fewer than 2 evidence items are downgraded below formal reporting threshold.
- **confidence_threshold_for_reporting**: Only hypotheses with confidence >= 0.6 are materialized as findings.
- **human_review_for_high_impact_or_thin_claims**: Potentially high-impact findings and thinly corroborated claims are flagged for analyst validation before operational use.
- **source_diversity_tracking**: Hypotheses record whether evidence came from limited or multiple analytic sources.

## Findings

### 1. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.79**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 98.159.33.51->10.128.239.57:3389, 10.128.239.57->98.159.33.51:7420, 149.50.116.107->10.128.239.57:3389, 10.128.239.57->149.50.116.107:59225, 10.128.239.57->147.45.112.186:21079
- Human Review Required: No
- Guardrail Flags: limited_source_diversity
- False Positive Risks:
  - Missing SNI may occur in privacy-focused or legacy environments and is not inherently malicious.
  - TLS on non-standard ports is suspicious but can still be legitimate.
- Missed Detection Risks:
  - If JA3 is unavailable, TLS detections rely on weaker metadata signals.
  - Encrypted malicious traffic with normal TLS fingerprints may not be flagged.
- Technical Limitations:
  - TLS analysis may be constrained by unavailable JA3, limited SNI visibility, or incomplete handshake metadata.
- Evidence:
  - [tls_analysis] suspicious_tls = 98.159.33.51->10.128.239.57:3389 (score=0.50) details={'entity': '98.159.33.51->10.128.239.57:3389', 'src_ip': '98.159.33.51', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 1, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Dec  4, 2025 04:23:54.838051000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->98.159.33.51:7420 (score=0.60) details={'entity': '10.128.239.57->98.159.33.51:7420', 'src_ip': '10.128.239.57', 'dst_ip': '98.159.33.51', 'dst_port': 7420, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  4, 2025 04:23:54.901189000 +08'}
  - [tls_analysis] suspicious_tls = 149.50.116.107->10.128.239.57:3389 (score=0.50) details={'entity': '149.50.116.107->10.128.239.57:3389', 'src_ip': '149.50.116.107', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 1, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Dec  4, 2025 05:08:23.044574000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->149.50.116.107:59225 (score=0.60) details={'entity': '10.128.239.57->149.50.116.107:59225', 'src_ip': '10.128.239.57', 'dst_ip': '149.50.116.107', 'dst_port': 59225, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  4, 2025 05:08:23.121661000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->147.45.112.186:21079 (score=0.60) details={'entity': '10.128.239.57->147.45.112.186:21079', 'src_ip': '10.128.239.57', 'dst_ip': '147.45.112.186', 'dst_port': 21079, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  4, 2025 09:33:10.792542000 +08'}

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

- 2026-04-12T14:54:40.934550Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:40.934865Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:40.935023Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:40.935027Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:40.935085Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:40.935102Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:40.935110Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:40.935146Z | materialize_findings | Generated 1 final findings