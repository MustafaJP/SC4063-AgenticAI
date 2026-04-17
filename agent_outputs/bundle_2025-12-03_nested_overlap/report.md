# Agentic Network Forensic Report — bundle_2025-12-03_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2025-12-03_nested_overlap` and identified **2 reportable finding(s)**. The highest-confidence finding was **External Sensitive Access** with confidence **1.00** and severity **HIGH**.

## Analysis Metrics

- Event Count: 122
- PCAP Count: 3
- Hypothesis Count: 2
- Finding Count: 2
- Analysis Runtime (seconds): 0.002
- Estimated Analysis Cost: 0.0
- Human Review Required Count: 0
- Guardrailed Hypothesis Count: 2

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
- Affected Entities: 194.165.17.11->10.128.239.57:3389, 91.199.163.12->10.128.239.57:3389, 147.45.112.188->10.128.239.57:3389, 147.45.112.181->10.128.239.57:3389, 194.165.16.167->10.128.239.57:3389, 45.227.254.152->10.128.239.57:3389, 179.60.146.33->10.128.239.57:3389
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
  - [external_access_analysis] external_sensitive_access = 194.165.17.11->10.128.239.57:3389 (score=0.90) details={'entity': '194.165.17.11->10.128.239.57:3389', 'src_ip': '194.165.17.11', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 10, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  3, 2025 06:28:06.792081000 +08'}
  - [external_access_analysis] external_sensitive_access = 91.199.163.12->10.128.239.57:3389 (score=0.90) details={'entity': '91.199.163.12->10.128.239.57:3389', 'src_ip': '91.199.163.12', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  3, 2025 07:02:13.933736000 +08'}
  - [external_access_analysis] external_sensitive_access = 147.45.112.188->10.128.239.57:3389 (score=0.90) details={'entity': '147.45.112.188->10.128.239.57:3389', 'src_ip': '147.45.112.188', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  3, 2025 07:02:14.064649000 +08'}
  - [external_access_analysis] external_sensitive_access = 147.45.112.181->10.128.239.57:3389 (score=0.80) details={'entity': '147.45.112.181->10.128.239.57:3389', 'src_ip': '147.45.112.181', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Dec  3, 2025 07:02:14.417383000 +08'}
  - [external_access_analysis] external_sensitive_access = 194.165.16.167->10.128.239.57:3389 (score=0.90) details={'entity': '194.165.16.167->10.128.239.57:3389', 'src_ip': '194.165.16.167', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  3, 2025 07:02:14.544142000 +08'}
  - [external_access_analysis] external_sensitive_access = 45.227.254.152->10.128.239.57:3389 (score=0.90) details={'entity': '45.227.254.152->10.128.239.57:3389', 'src_ip': '45.227.254.152', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  3, 2025 07:02:14.613014000 +08'}
  - [external_access_analysis] external_sensitive_access = 179.60.146.33->10.128.239.57:3389 (score=0.90) details={'entity': '179.60.146.33->10.128.239.57:3389', 'src_ip': '179.60.146.33', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  3, 2025 07:02:14.849358000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.78**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->91.199.163.12:54990, 10.128.239.57->147.45.112.188:30081, 10.128.239.57->193.3.19.42:28398, 10.128.239.57->45.227.254.152:48731
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.199.163.12:54990 (score=0.60) details={'entity': '10.128.239.57->91.199.163.12:54990', 'src_ip': '10.128.239.57', 'dst_ip': '91.199.163.12', 'dst_port': 54990, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  3, 2025 07:02:13.996119000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->147.45.112.188:30081 (score=0.60) details={'entity': '10.128.239.57->147.45.112.188:30081', 'src_ip': '10.128.239.57', 'dst_ip': '147.45.112.188', 'dst_port': 30081, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  3, 2025 07:02:14.182431000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->193.3.19.42:28398 (score=0.60) details={'entity': '10.128.239.57->193.3.19.42:28398', 'src_ip': '10.128.239.57', 'dst_ip': '193.3.19.42', 'dst_port': 28398, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  3, 2025 07:02:14.241530000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.227.254.152:48731 (score=0.60) details={'entity': '10.128.239.57->45.227.254.152:48731', 'src_ip': '10.128.239.57', 'dst_ip': '45.227.254.152', 'dst_port': 48731, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  3, 2025 07:02:14.775735000 +08'}

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

- 2026-04-16T18:55:06.690107Z | review_summary | Started summary-first investigation
- 2026-04-16T18:55:06.691413Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-16T18:55:06.691476Z | analyze_dns | Completed DNS analysis
- 2026-04-16T18:55:06.691479Z | analyze_http | Completed HTTP analysis
- 2026-04-16T18:55:06.691532Z | analyze_tls | Completed TLS analysis
- 2026-04-16T18:55:06.691542Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-16T18:55:06.691579Z | analyze_smb | Completed SMB analysis
- 2026-04-16T18:55:06.691687Z | analyze_external_access | Completed external access analysis
- 2026-04-16T18:55:06.691865Z | analyze_volumetric | Completed volumetric analysis
- 2026-04-16T18:55:06.691877Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-16T18:55:06.691914Z | materialize_findings | Generated 2 final findings