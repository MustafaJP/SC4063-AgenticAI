# Agentic Network Forensic Report — bundle_2025-12-09_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2025-12-09_nested_overlap` and identified **2 reportable finding(s)**. The highest-confidence finding was **External Sensitive Access** with confidence **1.00** and severity **HIGH**.

## Analysis Metrics

- Event Count: 198
- PCAP Count: 5
- Hypothesis Count: 4
- Finding Count: 2
- Analysis Runtime (seconds): 0.003
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
- Affected Entities: 45.227.254.152->10.128.239.57:3389, 179.60.146.32->10.128.239.57:3389, 141.98.11.144->10.128.239.57:3389, 194.165.16.167->10.128.239.57:3389, 91.238.181.93->10.128.239.57:3389, 179.60.146.36->10.128.239.57:3389, 91.238.181.39->10.128.239.57:3389, 141.98.11.8->10.128.239.57:3389, 147.45.112.181->10.128.239.57:3389, 88.214.25.125->10.128.239.57:3389, 88.214.25.121->10.128.239.57:3389, 91.238.181.10->10.128.239.57:3389
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
  - [external_access_analysis] external_sensitive_access = 45.227.254.152->10.128.239.57:3389 (score=0.90) details={'entity': '45.227.254.152->10.128.239.57:3389', 'src_ip': '45.227.254.152', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 5, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  9, 2025 03:31:37.362117000 +08'}
  - [external_access_analysis] external_sensitive_access = 179.60.146.32->10.128.239.57:3389 (score=0.90) details={'entity': '179.60.146.32->10.128.239.57:3389', 'src_ip': '179.60.146.32', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  9, 2025 03:31:37.515665000 +08'}
  - [external_access_analysis] external_sensitive_access = 141.98.11.144->10.128.239.57:3389 (score=0.80) details={'entity': '141.98.11.144->10.128.239.57:3389', 'src_ip': '141.98.11.144', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Dec  9, 2025 03:31:37.730456000 +08'}
  - [external_access_analysis] external_sensitive_access = 194.165.16.167->10.128.239.57:3389 (score=0.90) details={'entity': '194.165.16.167->10.128.239.57:3389', 'src_ip': '194.165.16.167', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 8, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  9, 2025 03:31:38.187175000 +08'}
  - [external_access_analysis] external_sensitive_access = 91.238.181.93->10.128.239.57:3389 (score=0.90) details={'entity': '91.238.181.93->10.128.239.57:3389', 'src_ip': '91.238.181.93', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 10, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  9, 2025 03:42:45.866176000 +08'}
  - [external_access_analysis] external_sensitive_access = 179.60.146.36->10.128.239.57:3389 (score=0.90) details={'entity': '179.60.146.36->10.128.239.57:3389', 'src_ip': '179.60.146.36', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 12, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  9, 2025 04:09:33.296005000 +08'}
  - [external_access_analysis] external_sensitive_access = 91.238.181.39->10.128.239.57:3389 (score=0.90) details={'entity': '91.238.181.39->10.128.239.57:3389', 'src_ip': '91.238.181.39', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 9, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  9, 2025 04:09:33.439010000 +08'}
  - [external_access_analysis] external_sensitive_access = 141.98.11.8->10.128.239.57:3389 (score=0.80) details={'entity': '141.98.11.8->10.128.239.57:3389', 'src_ip': '141.98.11.8', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Dec  9, 2025 04:09:33.555131000 +08'}
  - [external_access_analysis] external_sensitive_access = 147.45.112.181->10.128.239.57:3389 (score=0.90) details={'entity': '147.45.112.181->10.128.239.57:3389', 'src_ip': '147.45.112.181', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 6, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  9, 2025 08:35:16.491688000 +08'}
  - [external_access_analysis] external_sensitive_access = 88.214.25.125->10.128.239.57:3389 (score=0.90) details={'entity': '88.214.25.125->10.128.239.57:3389', 'src_ip': '88.214.25.125', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  9, 2025 08:35:16.920170000 +08'}
  - [external_access_analysis] external_sensitive_access = 88.214.25.121->10.128.239.57:3389 (score=0.90) details={'entity': '88.214.25.121->10.128.239.57:3389', 'src_ip': '88.214.25.121', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 6, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec  9, 2025 08:35:17.180768000 +08'}
  - [external_access_analysis] external_sensitive_access = 91.238.181.10->10.128.239.57:3389 (score=0.80) details={'entity': '91.238.181.10->10.128.239.57:3389', 'src_ip': '91.238.181.10', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Dec  9, 2025 20:47:42.631677000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.83**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->194.165.16.167:26425, 10.128.239.57->45.227.254.152:8136, 10.128.239.57->91.238.181.93:27205, 10.128.239.57->179.60.146.36:50607, 10.128.239.57->147.45.112.181:2422, 10.128.239.57->88.214.25.121:4781, 10.128.239.57->88.214.25.125:7761, 10.128.239.57->179.60.146.36:64260
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->194.165.16.167:26425 (score=0.60) details={'entity': '10.128.239.57->194.165.16.167:26425', 'src_ip': '10.128.239.57', 'dst_ip': '194.165.16.167', 'dst_port': 26425, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 03:31:37.307635000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.227.254.152:8136 (score=0.60) details={'entity': '10.128.239.57->45.227.254.152:8136', 'src_ip': '10.128.239.57', 'dst_ip': '45.227.254.152', 'dst_port': 8136, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 03:31:37.905295000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.93:27205 (score=0.60) details={'entity': '10.128.239.57->91.238.181.93:27205', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.93', 'dst_port': 27205, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 03:42:46.335899000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.36:50607 (score=0.60) details={'entity': '10.128.239.57->179.60.146.36:50607', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'dst_port': 50607, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 04:09:33.376012000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->147.45.112.181:2422 (score=0.60) details={'entity': '10.128.239.57->147.45.112.181:2422', 'src_ip': '10.128.239.57', 'dst_ip': '147.45.112.181', 'dst_port': 2422, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 08:35:16.550783000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->88.214.25.121:4781 (score=0.60) details={'entity': '10.128.239.57->88.214.25.121:4781', 'src_ip': '10.128.239.57', 'dst_ip': '88.214.25.121', 'dst_port': 4781, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 08:35:16.852634000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->88.214.25.125:7761 (score=0.60) details={'entity': '10.128.239.57->88.214.25.125:7761', 'src_ip': '10.128.239.57', 'dst_ip': '88.214.25.125', 'dst_port': 7761, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 08:35:16.980396000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->147.45.112.181:2422 (score=0.60) details={'entity': '10.128.239.57->147.45.112.181:2422', 'src_ip': '10.128.239.57', 'dst_ip': '147.45.112.181', 'dst_port': 2422, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 08:35:17.120799000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.36:64260 (score=0.60) details={'entity': '10.128.239.57->179.60.146.36:64260', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'dst_port': 64260, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 20:47:42.575579000 +08'}

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

- 2026-04-16T18:55:06.738739Z | review_summary | Started summary-first investigation
- 2026-04-16T18:55:06.741347Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-16T18:55:06.741467Z | analyze_dns | Completed DNS analysis
- 2026-04-16T18:55:06.741469Z | analyze_http | Completed HTTP analysis
- 2026-04-16T18:55:06.741545Z | analyze_tls | Completed TLS analysis
- 2026-04-16T18:55:06.741560Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-16T18:55:06.741609Z | analyze_smb | Completed SMB analysis
- 2026-04-16T18:55:06.741816Z | analyze_external_access | Completed external access analysis
- 2026-04-16T18:55:06.742135Z | analyze_volumetric | Completed volumetric analysis
- 2026-04-16T18:55:06.742158Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-16T18:55:06.742194Z | materialize_findings | Generated 2 final findings