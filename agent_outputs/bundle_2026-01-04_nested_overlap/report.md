# Agentic Network Forensic Report — bundle_2026-01-04_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-04_nested_overlap` and identified **3 reportable finding(s)**. The highest-confidence finding was **External Sensitive Access** with confidence **1.00** and severity **HIGH**.

## Analysis Metrics

- Event Count: 152
- PCAP Count: 4
- Hypothesis Count: 4
- Finding Count: 3
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
- Affected Entities: 179.60.146.37->10.128.239.57:3389, 141.98.11.109->10.128.239.57:3389, 57.129.133.249->10.128.239.57:3389, 98.159.33.51->10.128.239.57:3389
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
  - [external_access_analysis] external_sensitive_access = 179.60.146.37->10.128.239.57:3389 (score=0.90) details={'entity': '179.60.146.37->10.128.239.57:3389', 'src_ip': '179.60.146.37', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 6, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan  4, 2026 06:29:38.994363000 +08'}
  - [external_access_analysis] external_sensitive_access = 141.98.11.109->10.128.239.57:3389 (score=0.90) details={'entity': '141.98.11.109->10.128.239.57:3389', 'src_ip': '141.98.11.109', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 20, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan  4, 2026 16:36:44.335395000 +08'}
  - [external_access_analysis] external_sensitive_access = 57.129.133.249->10.128.239.57:3389 (score=0.90) details={'entity': '57.129.133.249->10.128.239.57:3389', 'src_ip': '57.129.133.249', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan  4, 2026 16:36:44.946620000 +08'}
  - [external_access_analysis] external_sensitive_access = 98.159.33.51->10.128.239.57:3389 (score=0.90) details={'entity': '98.159.33.51->10.128.239.57:3389', 'src_ip': '98.159.33.51', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 7, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan  4, 2026 19:09:49.149645000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.83**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->179.60.146.37:51394, 10.128.239.57->45.227.254.3:12976, 10.128.239.57->141.98.11.109:48366, 10.128.239.57->98.159.33.51:3082
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.37:51394 (score=0.60) details={'entity': '10.128.239.57->179.60.146.37:51394', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.37', 'dst_port': 51394, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 06:29:39.054711000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.227.254.3:12976 (score=0.60) details={'entity': '10.128.239.57->45.227.254.3:12976', 'src_ip': '10.128.239.57', 'dst_ip': '45.227.254.3', 'dst_port': 12976, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 06:29:39.298886000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.37:51394 (score=0.60) details={'entity': '10.128.239.57->179.60.146.37:51394', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.37', 'dst_port': 51394, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 06:29:39.609529000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.109:48366 (score=0.60) details={'entity': '10.128.239.57->141.98.11.109:48366', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.109', 'dst_port': 48366, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 16:36:44.784565000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.109:48366 (score=0.60) details={'entity': '10.128.239.57->141.98.11.109:48366', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.109', 'dst_port': 48366, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 16:36:45.299688000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->98.159.33.51:3082 (score=0.60) details={'entity': '10.128.239.57->98.159.33.51:3082', 'src_ip': '10.128.239.57', 'dst_ip': '98.159.33.51', 'dst_port': 3082, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 19:09:50.082233000 +08'}

### 3. Potential Data Exfiltration
- Severity: **HIGH**
- Confidence: **0.60**
- MITRE ATT&CK: T1048, T1041, T1567
- Description: Large or frequent outbound transfers to external host suggest data exfiltration.
- Recommendation: Block the destination IP, isolate the source host, and forensically examine what data may have been transferred.
- Affected Entities: 10.128.239.57->179.60.146.37, 10.128.239.21->185.159.197.3, 10.128.239.57->141.98.11.109, 10.128.239.57->98.159.33.51
- Human Review Required: No
- Guardrail Flags: limited_source_diversity
- False Positive Risks:
  - Large legitimate uploads (backups, cloud sync, CI/CD) may trigger volumetric thresholds.
- Missed Detection Risks:
  - Slow, low-volume exfiltration may stay below detection thresholds.
  - Encrypted exfiltration via legitimate services may not be flagged.
- Technical Limitations:
  - Volumetric analysis detects transfer patterns, not content — payload inspection requires decryption.
- Evidence:
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->179.60.146.37 (score=0.40) details={'entity': '10.128.239.57->179.60.146.37', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.37', 'session_count': 6, 'total_bytes': 0, 'ports_used': [51394], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Jan  4, 2026 06:29:39.054711000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.21->185.159.197.3 (score=0.30) details={'entity': '10.128.239.21->185.159.197.3', 'src_ip': '10.128.239.21', 'dst_ip': '185.159.197.3', 'session_count': 6, 'total_bytes': 0, 'ports_used': [53], 'reasons': ['high_session_count'], 'event_timestamp': 'Jan  4, 2026 06:29:39.240696000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->141.98.11.109 (score=0.60) details={'entity': '10.128.239.57->141.98.11.109', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.109', 'session_count': 10, 'total_bytes': 0, 'ports_used': [34078, 48366], 'reasons': ['high_session_count', 'very_high_session_count', 'high_port_usage'], 'event_timestamp': 'Jan  4, 2026 16:36:44.391855000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->98.159.33.51 (score=0.30) details={'entity': '10.128.239.57->98.159.33.51', 'src_ip': '10.128.239.57', 'dst_ip': '98.159.33.51', 'session_count': 5, 'total_bytes': 0, 'ports_used': [3082], 'reasons': ['high_session_count'], 'event_timestamp': 'Jan  4, 2026 19:09:49.206713000 +08'}

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

- 2026-04-16T18:55:06.891655Z | review_summary | Started summary-first investigation
- 2026-04-16T18:55:06.893849Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-16T18:55:06.893941Z | analyze_dns | Completed DNS analysis
- 2026-04-16T18:55:06.893944Z | analyze_http | Completed HTTP analysis
- 2026-04-16T18:55:06.893994Z | analyze_tls | Completed TLS analysis
- 2026-04-16T18:55:06.894006Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-16T18:55:06.894043Z | analyze_smb | Completed SMB analysis
- 2026-04-16T18:55:06.894161Z | analyze_external_access | Completed external access analysis
- 2026-04-16T18:55:06.894386Z | analyze_volumetric | Completed volumetric analysis
- 2026-04-16T18:55:06.894403Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-16T18:55:06.894451Z | materialize_findings | Generated 3 final findings