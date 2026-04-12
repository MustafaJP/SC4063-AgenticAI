# Agentic Network Forensic Report — bundle_2026-01-21_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-21_nested_overlap` and identified **1 reportable finding(s)**. The highest-confidence finding was **Suspicious TLS Session** with confidence **0.83** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 127
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
- Affected Entities: 185.16.39.19->10.128.239.57:3389, 10.128.239.57->185.16.39.19:48062, 10.128.239.57->141.98.11.81:32555, 10.128.239.57->179.60.146.32:53128, 10.128.239.57->179.60.146.32:54130, 20.42.65.91->10.128.239.20:57440, 10.128.239.20->20.42.65.91:443
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
  - [tls_analysis] suspicious_tls = 185.16.39.19->10.128.239.57:3389 (score=0.60) details={'entity': '185.16.39.19->10.128.239.57:3389', 'src_ip': '185.16.39.19', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 11:18:11.221207000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->185.16.39.19:48062 (score=0.60) details={'entity': '10.128.239.57->185.16.39.19:48062', 'src_ip': '10.128.239.57', 'dst_ip': '185.16.39.19', 'dst_port': 48062, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 11:18:11.253789000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.81:32555 (score=0.60) details={'entity': '10.128.239.57->141.98.11.81:32555', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.81', 'dst_port': 32555, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 11:18:11.334347000 +08'}
  - [tls_analysis] suspicious_tls = 185.16.39.19->10.128.239.57:3389 (score=0.60) details={'entity': '185.16.39.19->10.128.239.57:3389', 'src_ip': '185.16.39.19', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '1', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 11:18:11.723811000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.32:53128 (score=0.60) details={'entity': '10.128.239.57->179.60.146.32:53128', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.32', 'dst_port': 53128, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 11:18:11.911972000 +08'}
  - [tls_analysis] suspicious_tls = 185.16.39.19->10.128.239.57:3389 (score=0.70) details={'entity': '185.16.39.19->10.128.239.57:3389', 'src_ip': '185.16.39.19', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 11:18:11.980934000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->185.16.39.19:48062 (score=0.60) details={'entity': '10.128.239.57->185.16.39.19:48062', 'src_ip': '10.128.239.57', 'dst_ip': '185.16.39.19', 'dst_port': 48062, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 11:18:12.014856000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.32:54130 (score=0.60) details={'entity': '10.128.239.57->179.60.146.32:54130', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.32', 'dst_port': 54130, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 11:18:12.061128000 +08'}
  - [tls_analysis] suspicious_tls = 20.42.65.91->10.128.239.20:57440 (score=0.60) details={'entity': '20.42.65.91->10.128.239.20:57440', 'src_ip': '20.42.65.91', 'dst_ip': '10.128.239.20', 'dst_port': 57440, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 17:47:18.202159000 +08'}
  - [tls_analysis] suspicious_tls = 20.42.65.91->10.128.239.20:57440 (score=0.60) details={'entity': '20.42.65.91->10.128.239.20:57440', 'src_ip': '20.42.65.91', 'dst_ip': '10.128.239.20', 'dst_port': 57440, 'ja3': '', 'sni': '', 'handshake_type': '2', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 17:47:18.346025000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.20->20.42.65.91:443 (score=0.50) details={'entity': '10.128.239.20->20.42.65.91:443', 'src_ip': '10.128.239.20', 'dst_ip': '20.42.65.91', 'dst_port': 443, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'unusual_handshake_type'], 'event_timestamp': 'Jan 21, 2026 17:47:18.414965000 +08'}
  - [tls_analysis] suspicious_tls = 20.42.65.91->10.128.239.20:57440 (score=0.60) details={'entity': '20.42.65.91->10.128.239.20:57440', 'src_ip': '20.42.65.91', 'dst_ip': '10.128.239.20', 'dst_port': 57440, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 17:47:18.448698000 +08'}
  - [tls_analysis] suspicious_tls = 20.42.65.91->10.128.239.20:57440 (score=0.60) details={'entity': '20.42.65.91->10.128.239.20:57440', 'src_ip': '20.42.65.91', 'dst_ip': '10.128.239.20', 'dst_port': 57440, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 17:47:18.482454000 +08'}
  - [tls_analysis] suspicious_tls = 20.42.65.91->10.128.239.20:57440 (score=0.60) details={'entity': '20.42.65.91->10.128.239.20:57440', 'src_ip': '20.42.65.91', 'dst_ip': '10.128.239.20', 'dst_port': 57440, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 17:47:18.837593000 +08'}

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

- 2026-04-12T14:54:41.202951Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:41.203238Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:41.203248Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:41.203251Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:41.203349Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:41.203362Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:41.203371Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:41.203388Z | materialize_findings | Generated 1 final findings