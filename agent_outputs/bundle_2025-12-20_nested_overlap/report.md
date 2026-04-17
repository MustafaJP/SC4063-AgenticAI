# Agentic Network Forensic Report — bundle_2025-12-20_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2025-12-20_nested_overlap` and identified **2 reportable finding(s)**. The highest-confidence finding was **External Sensitive Access** with confidence **1.00** and severity **HIGH**.

## Analysis Metrics

- Event Count: 108
- PCAP Count: 3
- Hypothesis Count: 4
- Finding Count: 2
- Analysis Runtime (seconds): 0.002
- Estimated Analysis Cost: 0.0
- Human Review Required Count: 0
- Guardrailed Hypothesis Count: 4

## Safety Controls and Guardrails

- **minimum_evidence_requirement**: Hypotheses with fewer than 2 evidence items are downgraded below formal reporting threshold.
- **confidence_threshold_for_reporting**: Only hypotheses with confidence >= 0.6 are materialized as findings.
- **human_review_for_high_impact_or_thin_claims**: Potentially high-impact findings and thinly corroborated claims are flagged for analyst validation before operational use.
- **source_diversity_tracking**: Hypotheses record whether evidence came from limited or multiple analytic sources.

## Findings

### 1. External Sensitive Access
- Severity: **HIGH**
- Confidence: **1.00**
- MITRE ATT&CK: T1133, T1078, T1021.001
- Description: External IP accessed internal host on sensitive port, suggesting unauthorized remote access.
- Recommendation: Verify authorization of external access, reset credentials on accessed hosts, and review for signs of post-exploitation activity.
- Affected Entities: 88.214.25.123->10.128.239.57:3389, 98.159.33.51->10.128.239.57:3389, 88.214.25.115->10.128.239.57:3389
- Human Review Required: No
- Guardrail Flags: limited_source_diversity
- False Positive Risks:
  - Legitimate remote administration via RDP or SSH from authorized external IPs.
  - VPN or jump-host traffic may appear as external access.
- Missed Detection Risks:
  - Access via VPN tunnels that terminate internally will not appear as external.
- Technical Limitations:
  - Cannot distinguish between authorized and unauthorized remote access without credential context.
- Evidence:
  - [external_access_analysis] external_sensitive_access = 88.214.25.123->10.128.239.57:3389 (score=0.90) details={'entity': '88.214.25.123->10.128.239.57:3389', 'src_ip': '88.214.25.123', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 11, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 20, 2025 04:16:32.211054000 +08'}
  - [external_access_analysis] external_sensitive_access = 98.159.33.51->10.128.239.57:3389 (score=0.90) details={'entity': '98.159.33.51->10.128.239.57:3389', 'src_ip': '98.159.33.51', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 6, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 20, 2025 04:16:32.391324000 +08'}
  - [external_access_analysis] external_sensitive_access = 88.214.25.115->10.128.239.57:3389 (score=0.80) details={'entity': '88.214.25.115->10.128.239.57:3389', 'src_ip': '88.214.25.115', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Dec 20, 2025 04:16:32.530363000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.73**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->88.214.25.123:3500, 10.128.239.57->98.159.33.51:56387
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->88.214.25.123:3500 (score=0.60) details={'entity': '10.128.239.57->88.214.25.123:3500', 'src_ip': '10.128.239.57', 'dst_ip': '88.214.25.123', 'dst_port': 3500, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 20, 2025 04:16:32.328557000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->98.159.33.51:56387 (score=0.60) details={'entity': '10.128.239.57->98.159.33.51:56387', 'src_ip': '10.128.239.57', 'dst_ip': '98.159.33.51', 'dst_port': 56387, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 20, 2025 04:16:32.473095000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->88.214.25.123:3500 (score=0.60) details={'entity': '10.128.239.57->88.214.25.123:3500', 'src_ip': '10.128.239.57', 'dst_ip': '88.214.25.123', 'dst_port': 3500, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 20, 2025 04:16:32.984479000 +08'}

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

- 2026-04-16T18:55:06.833158Z | review_summary | Started summary-first investigation
- 2026-04-16T18:55:06.834695Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-16T18:55:06.834743Z | analyze_dns | Completed DNS analysis
- 2026-04-16T18:55:06.834745Z | analyze_http | Completed HTTP analysis
- 2026-04-16T18:55:06.834778Z | analyze_tls | Completed TLS analysis
- 2026-04-16T18:55:06.834787Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-16T18:55:06.834810Z | analyze_smb | Completed SMB analysis
- 2026-04-16T18:55:06.834883Z | analyze_external_access | Completed external access analysis
- 2026-04-16T18:55:06.835016Z | analyze_volumetric | Completed volumetric analysis
- 2026-04-16T18:55:06.835029Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-16T18:55:06.835058Z | materialize_findings | Generated 2 final findings