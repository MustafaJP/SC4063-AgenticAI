# Agentic Network Forensic Report — bundle_2025-12-15_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2025-12-15_nested_overlap` and identified **1 reportable finding(s)**. The highest-confidence finding was **Suspicious TLS Session** with confidence **0.83** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 117
- PCAP Count: 4
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
- Affected Entities: 10.128.239.57->91.238.181.10:54874, 10.128.239.57->141.98.11.114:13853, 10.128.239.57->178.20.129.235:50722, 10.128.239.57->141.98.11.49:54971, 10.128.239.57->195.211.190.189:53789
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.10:54874 (score=0.60) details={'entity': '10.128.239.57->91.238.181.10:54874', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.10', 'dst_port': 54874, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 01:15:54.490663000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.114:13853 (score=0.60) details={'entity': '10.128.239.57->141.98.11.114:13853', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.114', 'dst_port': 13853, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 01:15:54.662070000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->178.20.129.235:50722 (score=0.60) details={'entity': '10.128.239.57->178.20.129.235:50722', 'src_ip': '10.128.239.57', 'dst_ip': '178.20.129.235', 'dst_port': 50722, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 01:15:55.079974000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.49:54971 (score=0.60) details={'entity': '10.128.239.57->141.98.11.49:54971', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.49', 'dst_port': 54971, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 04:24:50.822258000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->195.211.190.189:53789 (score=0.60) details={'entity': '10.128.239.57->195.211.190.189:53789', 'src_ip': '10.128.239.57', 'dst_ip': '195.211.190.189', 'dst_port': 53789, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 17:26:59.236761000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->195.211.190.189:53789 (score=0.60) details={'entity': '10.128.239.57->195.211.190.189:53789', 'src_ip': '10.128.239.57', 'dst_ip': '195.211.190.189', 'dst_port': 53789, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 17:26:59.335255000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->195.211.190.189:53789 (score=0.60) details={'entity': '10.128.239.57->195.211.190.189:53789', 'src_ip': '10.128.239.57', 'dst_ip': '195.211.190.189', 'dst_port': 53789, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 17:26:59.433232000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->195.211.190.189:53789 (score=0.60) details={'entity': '10.128.239.57->195.211.190.189:53789', 'src_ip': '10.128.239.57', 'dst_ip': '195.211.190.189', 'dst_port': 53789, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 17:26:59.528445000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->195.211.190.189:53789 (score=0.60) details={'entity': '10.128.239.57->195.211.190.189:53789', 'src_ip': '10.128.239.57', 'dst_ip': '195.211.190.189', 'dst_port': 53789, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 17:26:59.627025000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->195.211.190.189:53789 (score=0.60) details={'entity': '10.128.239.57->195.211.190.189:53789', 'src_ip': '10.128.239.57', 'dst_ip': '195.211.190.189', 'dst_port': 53789, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 17:26:59.724062000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->195.211.190.189:53789 (score=0.60) details={'entity': '10.128.239.57->195.211.190.189:53789', 'src_ip': '10.128.239.57', 'dst_ip': '195.211.190.189', 'dst_port': 53789, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 17:26:59.821172000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->195.211.190.189:53789 (score=0.60) details={'entity': '10.128.239.57->195.211.190.189:53789', 'src_ip': '10.128.239.57', 'dst_ip': '195.211.190.189', 'dst_port': 53789, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 17:26:59.977295000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->195.211.190.189:53789 (score=0.60) details={'entity': '10.128.239.57->195.211.190.189:53789', 'src_ip': '10.128.239.57', 'dst_ip': '195.211.190.189', 'dst_port': 53789, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 17:27:00.082604000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->195.211.190.189:53789 (score=0.60) details={'entity': '10.128.239.57->195.211.190.189:53789', 'src_ip': '10.128.239.57', 'dst_ip': '195.211.190.189', 'dst_port': 53789, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 14, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 15, 2025 17:27:00.179101000 +08'}

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

- 2026-04-12T14:54:41.017333Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:41.017537Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:41.017586Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:41.017588Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:41.017649Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:41.017661Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:41.017668Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:41.017686Z | materialize_findings | Generated 1 final findings