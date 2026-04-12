# Agentic Network Forensic Report — bundle_2026-01-18_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-18_nested_overlap` and identified **1 reportable finding(s)**. The highest-confidence finding was **Suspicious TLS Session** with confidence **0.83** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 213
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
- Confidence: **0.83**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->194.165.17.11:35610, 10.128.239.57->91.238.181.91:30446, 10.128.239.57->88.214.25.123:19096, 10.128.239.57->179.60.146.37:60950, 10.128.239.57->147.45.112.185:35895, 10.128.239.57->147.45.112.186:34874, 10.128.239.57->91.238.181.6:16036, 10.128.239.57->141.98.11.100:48695
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->194.165.17.11:35610 (score=0.60) details={'entity': '10.128.239.57->194.165.17.11:35610', 'src_ip': '10.128.239.57', 'dst_ip': '194.165.17.11', 'dst_port': 35610, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 18, 2026 01:42:23.242765000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.91:30446 (score=0.60) details={'entity': '10.128.239.57->91.238.181.91:30446', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.91', 'dst_port': 30446, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 18, 2026 01:42:23.324156000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->88.214.25.123:19096 (score=0.60) details={'entity': '10.128.239.57->88.214.25.123:19096', 'src_ip': '10.128.239.57', 'dst_ip': '88.214.25.123', 'dst_port': 19096, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 18, 2026 01:42:23.405653000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.37:60950 (score=0.60) details={'entity': '10.128.239.57->179.60.146.37:60950', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.37', 'dst_port': 60950, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 18, 2026 03:59:25.312843000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->147.45.112.185:35895 (score=0.60) details={'entity': '10.128.239.57->147.45.112.185:35895', 'src_ip': '10.128.239.57', 'dst_ip': '147.45.112.185', 'dst_port': 35895, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 18, 2026 03:59:25.663831000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->147.45.112.186:34874 (score=0.60) details={'entity': '10.128.239.57->147.45.112.186:34874', 'src_ip': '10.128.239.57', 'dst_ip': '147.45.112.186', 'dst_port': 34874, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 18, 2026 03:59:25.805361000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.6:16036 (score=0.60) details={'entity': '10.128.239.57->91.238.181.6:16036', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.6', 'dst_port': 16036, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 18, 2026 17:12:13.843082000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.100:48695 (score=0.60) details={'entity': '10.128.239.57->141.98.11.100:48695', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.100', 'dst_port': 48695, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 18, 2026 17:12:13.902496000 +08'}

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

- 2026-04-12T14:54:41.185864Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:41.186313Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:41.186405Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:41.186407Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:41.186469Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:41.186488Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:41.186494Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:41.186515Z | materialize_findings | Generated 1 final findings