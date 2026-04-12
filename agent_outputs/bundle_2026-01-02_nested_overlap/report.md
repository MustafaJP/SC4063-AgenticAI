# Agentic Network Forensic Report — bundle_2026-01-02_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-02_nested_overlap` and identified **1 reportable finding(s)**. The highest-confidence finding was **Suspicious TLS Session** with confidence **0.83** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 84
- PCAP Count: 2
- Hypothesis Count: 1
- Finding Count: 1
- Analysis Runtime (seconds): 0.0
- Estimated Analysis Cost: 0.0
- Human Review Required Count: 0
- Guardrailed Hypothesis Count: 1

## Safety Controls and Guardrails

- **minimum_evidence_requirement**: Hypotheses with fewer than 2 evidence items are downgraded below formal reporting threshold.
- **confidence_threshold_for_reporting**: Only hypotheses with confidence >= 0.6 are materialized as findings.
- **human_review_for_high_impact_or_thin_claims**: Potentially high-impact findings and thinly corroborated claims are flagged for analyst validation before operational use.
- **source_diversity_tracking**: Hypotheses record whether evidence came from limited or multiple analytic sources.

## Findings

### 1. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.83**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->194.165.16.167:29737, 10.128.239.57->88.214.25.121:41245, 91.238.181.93->10.128.239.57:3389, 10.128.239.57->91.238.181.93:8728, 141.98.11.114->10.128.239.57:3389, 10.128.239.57->141.98.11.114:18890, 10.128.239.57->179.60.146.33:58944
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->194.165.16.167:29737 (score=0.60) details={'entity': '10.128.239.57->194.165.16.167:29737', 'src_ip': '10.128.239.57', 'dst_ip': '194.165.16.167', 'dst_port': 29737, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  2, 2026 11:35:30.638786000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->88.214.25.121:41245 (score=0.60) details={'entity': '10.128.239.57->88.214.25.121:41245', 'src_ip': '10.128.239.57', 'dst_ip': '88.214.25.121', 'dst_port': 41245, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  2, 2026 11:35:30.811485000 +08'}
  - [tls_analysis] suspicious_tls = 91.238.181.93->10.128.239.57:3389 (score=0.50) details={'entity': '91.238.181.93->10.128.239.57:3389', 'src_ip': '91.238.181.93', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 2, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Jan  2, 2026 11:35:31.216491000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.93:8728 (score=0.60) details={'entity': '10.128.239.57->91.238.181.93:8728', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.93', 'dst_port': 8728, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  2, 2026 11:35:31.276379000 +08'}
  - [tls_analysis] suspicious_tls = 141.98.11.114->10.128.239.57:3389 (score=0.60) details={'entity': '141.98.11.114->10.128.239.57:3389', 'src_ip': '141.98.11.114', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  2, 2026 18:12:14.106105000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.114:18890 (score=0.60) details={'entity': '10.128.239.57->141.98.11.114:18890', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.114', 'dst_port': 18890, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  2, 2026 18:12:14.162621000 +08'}
  - [tls_analysis] suspicious_tls = 141.98.11.114->10.128.239.57:3389 (score=0.60) details={'entity': '141.98.11.114->10.128.239.57:3389', 'src_ip': '141.98.11.114', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '1', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  2, 2026 18:12:14.361348000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.33:58944 (score=0.60) details={'entity': '10.128.239.57->179.60.146.33:58944', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.33', 'dst_port': 58944, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  2, 2026 18:12:14.859274000 +08'}
  - [tls_analysis] suspicious_tls = 141.98.11.114->10.128.239.57:3389 (score=0.70) details={'entity': '141.98.11.114->10.128.239.57:3389', 'src_ip': '141.98.11.114', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Jan  2, 2026 18:12:14.925116000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.114:18890 (score=0.60) details={'entity': '10.128.239.57->141.98.11.114:18890', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.114', 'dst_port': 18890, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  2, 2026 18:12:14.986416000 +08'}

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

- 2026-04-12T14:54:41.097108Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:41.097298Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:41.097350Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:41.097353Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:41.097423Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:41.097434Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:41.097442Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:41.097467Z | materialize_findings | Generated 1 final findings