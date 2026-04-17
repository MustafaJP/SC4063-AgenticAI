# Agentic Network Forensic Report — bundle_2026-01-21_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-21_nested_overlap` and identified **3 reportable finding(s)**. The highest-confidence finding was **External Sensitive Access** with confidence **1.00** and severity **HIGH**.

## Analysis Metrics

- Event Count: 127
- PCAP Count: 2
- Hypothesis Count: 4
- Finding Count: 3
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
- Affected Entities: 185.16.39.19->10.128.239.57:3389, 141.98.11.81->10.128.239.57:3389, 193.3.19.42->10.128.239.57:3389, 179.60.146.32->10.128.239.57:3389, 147.45.112.181->10.128.239.57:3389, 92.255.85.173->10.128.239.57:3389, 91.238.181.7->10.128.239.57:3389
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
  - [external_access_analysis] external_sensitive_access = 185.16.39.19->10.128.239.57:3389 (score=0.90) details={'entity': '185.16.39.19->10.128.239.57:3389', 'src_ip': '185.16.39.19', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 11, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 21, 2026 11:18:11.183439000 +08'}
  - [external_access_analysis] external_sensitive_access = 141.98.11.81->10.128.239.57:3389 (score=0.90) details={'entity': '141.98.11.81->10.128.239.57:3389', 'src_ip': '141.98.11.81', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 6, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 21, 2026 11:18:11.290087000 +08'}
  - [external_access_analysis] external_sensitive_access = 193.3.19.42->10.128.239.57:3389 (score=0.90) details={'entity': '193.3.19.42->10.128.239.57:3389', 'src_ip': '193.3.19.42', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 4, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 21, 2026 11:18:11.367284000 +08'}
  - [external_access_analysis] external_sensitive_access = 179.60.146.32->10.128.239.57:3389 (score=0.90) details={'entity': '179.60.146.32->10.128.239.57:3389', 'src_ip': '179.60.146.32', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 10, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 21, 2026 11:18:11.400755000 +08'}
  - [external_access_analysis] external_sensitive_access = 147.45.112.181->10.128.239.57:3389 (score=0.90) details={'entity': '147.45.112.181->10.128.239.57:3389', 'src_ip': '147.45.112.181', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 10, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 21, 2026 11:18:11.500111000 +08'}
  - [external_access_analysis] external_sensitive_access = 92.255.85.173->10.128.239.57:3389 (score=0.80) details={'entity': '92.255.85.173->10.128.239.57:3389', 'src_ip': '92.255.85.173', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Jan 21, 2026 11:18:11.684825000 +08'}
  - [external_access_analysis] external_sensitive_access = 91.238.181.7->10.128.239.57:3389 (score=0.90) details={'entity': '91.238.181.7->10.128.239.57:3389', 'src_ip': '91.238.181.7', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 7, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 21, 2026 17:47:17.867157000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.82**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->185.16.39.19:48062, 10.128.239.57->141.98.11.81:32555, 10.128.239.57->179.60.146.32:53128, 10.128.239.57->179.60.146.32:54130, 20.42.65.91->10.128.239.20:57440, 10.128.239.20->20.42.65.91:443
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->185.16.39.19:48062 (score=0.60) details={'entity': '10.128.239.57->185.16.39.19:48062', 'src_ip': '10.128.239.57', 'dst_ip': '185.16.39.19', 'dst_port': 48062, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 11:18:11.253789000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.81:32555 (score=0.60) details={'entity': '10.128.239.57->141.98.11.81:32555', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.81', 'dst_port': 32555, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 11:18:11.334347000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.32:53128 (score=0.60) details={'entity': '10.128.239.57->179.60.146.32:53128', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.32', 'dst_port': 53128, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 11:18:11.911972000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->185.16.39.19:48062 (score=0.60) details={'entity': '10.128.239.57->185.16.39.19:48062', 'src_ip': '10.128.239.57', 'dst_ip': '185.16.39.19', 'dst_port': 48062, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 11:18:12.014856000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.32:54130 (score=0.60) details={'entity': '10.128.239.57->179.60.146.32:54130', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.32', 'dst_port': 54130, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 11:18:12.061128000 +08'}
  - [tls_analysis] suspicious_tls = 20.42.65.91->10.128.239.20:57440 (score=0.60) details={'entity': '20.42.65.91->10.128.239.20:57440', 'src_ip': '20.42.65.91', 'dst_ip': '10.128.239.20', 'dst_port': 57440, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 17:47:18.202159000 +08'}
  - [tls_analysis] suspicious_tls = 20.42.65.91->10.128.239.20:57440 (score=0.60) details={'entity': '20.42.65.91->10.128.239.20:57440', 'src_ip': '20.42.65.91', 'dst_ip': '10.128.239.20', 'dst_port': 57440, 'ja3': '', 'sni': '', 'handshake_type': '2', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 17:47:18.346025000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.20->20.42.65.91:443 (score=0.50) details={'entity': '10.128.239.20->20.42.65.91:443', 'src_ip': '10.128.239.20', 'dst_ip': '20.42.65.91', 'dst_port': 443, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'unusual_handshake_type'], 'event_timestamp': 'Jan 21, 2026 17:47:18.414965000 +08'}
  - [tls_analysis] suspicious_tls = 20.42.65.91->10.128.239.20:57440 (score=0.60) details={'entity': '20.42.65.91->10.128.239.20:57440', 'src_ip': '20.42.65.91', 'dst_ip': '10.128.239.20', 'dst_port': 57440, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 17:47:18.448698000 +08'}
  - [tls_analysis] suspicious_tls = 20.42.65.91->10.128.239.20:57440 (score=0.60) details={'entity': '20.42.65.91->10.128.239.20:57440', 'src_ip': '20.42.65.91', 'dst_ip': '10.128.239.20', 'dst_port': 57440, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 17:47:18.482454000 +08'}
  - [tls_analysis] suspicious_tls = 20.42.65.91->10.128.239.20:57440 (score=0.60) details={'entity': '20.42.65.91->10.128.239.20:57440', 'src_ip': '20.42.65.91', 'dst_ip': '10.128.239.20', 'dst_port': 57440, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 5, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 21, 2026 17:47:18.837593000 +08'}

### 3. Potential Data Exfiltration
- Severity: **HIGH**
- Confidence: **0.70**
- MITRE ATT&CK: T1048, T1041, T1567
- Description: Large or frequent outbound transfers to external host suggest data exfiltration.
- Recommendation: Block the destination IP, isolate the source host, and forensically examine what data may have been transferred.
- Affected Entities: 10.128.239.57->185.16.39.19, 10.128.239.57->141.98.11.81, 10.128.239.57->179.60.146.32, 10.128.239.20->20.42.65.91
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
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->185.16.39.19 (score=0.40) details={'entity': '10.128.239.57->185.16.39.19', 'src_ip': '10.128.239.57', 'dst_ip': '185.16.39.19', 'session_count': 6, 'total_bytes': 0, 'ports_used': [48062], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Jan 21, 2026 11:18:11.253789000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->141.98.11.81 (score=0.40) details={'entity': '10.128.239.57->141.98.11.81', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.81', 'session_count': 5, 'total_bytes': 0, 'ports_used': [32555], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Jan 21, 2026 11:18:11.334347000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->179.60.146.32 (score=0.40) details={'entity': '10.128.239.57->179.60.146.32', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.32', 'session_count': 8, 'total_bytes': 0, 'ports_used': [53128, 54130], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Jan 21, 2026 11:18:11.433924000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.20->20.42.65.91 (score=0.80) details={'entity': '10.128.239.20->20.42.65.91', 'src_ip': '10.128.239.20', 'dst_ip': '20.42.65.91', 'session_count': 29, 'total_bytes': 0, 'ports_used': [443], 'reasons': ['high_session_count', 'very_high_session_count', 'excessive_sessions', 'https_exfil_channel'], 'event_timestamp': 'Jan 21, 2026 17:47:18.022943000 +08'}

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

- 2026-04-16T18:55:06.993722Z | review_summary | Started summary-first investigation
- 2026-04-16T18:55:06.995402Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-16T18:55:06.995411Z | analyze_dns | Completed DNS analysis
- 2026-04-16T18:55:06.995413Z | analyze_http | Completed HTTP analysis
- 2026-04-16T18:55:06.995494Z | analyze_tls | Completed TLS analysis
- 2026-04-16T18:55:06.995504Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-16T18:55:06.995530Z | analyze_smb | Completed SMB analysis
- 2026-04-16T18:55:06.995687Z | analyze_external_access | Completed external access analysis
- 2026-04-16T18:55:06.995957Z | analyze_volumetric | Completed volumetric analysis
- 2026-04-16T18:55:06.995978Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-16T18:55:06.996012Z | materialize_findings | Generated 3 final findings