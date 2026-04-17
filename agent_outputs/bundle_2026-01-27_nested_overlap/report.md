# Agentic Network Forensic Report — bundle_2026-01-27_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-27_nested_overlap` and identified **3 reportable finding(s)**. The highest-confidence finding was **External Sensitive Access** with confidence **1.00** and severity **HIGH**.

## Analysis Metrics

- Event Count: 285
- PCAP Count: 4
- Hypothesis Count: 4
- Finding Count: 3
- Analysis Runtime (seconds): 0.005
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
- Affected Entities: 91.238.181.95->10.128.239.57:3389, 185.42.12.42->10.128.239.57:3389, 179.60.146.36->10.128.239.57:3389, 141.98.11.8->10.128.239.57:3389, 91.238.181.7->10.128.239.57:3389, 179.60.146.37->10.128.239.57:3389, 80.75.212.32->10.128.239.57:3389, 91.238.181.10->10.128.239.57:3389, 80.91.223.58->10.128.239.57:3389, 88.214.25.121->10.128.239.57:3389, 141.98.83.70->10.128.239.57:3389, 179.60.146.33->10.128.239.57:3389, 103.180.176.136->10.128.239.57:3389
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
  - [external_access_analysis] external_sensitive_access = 91.238.181.95->10.128.239.57:3389 (score=0.90) details={'entity': '91.238.181.95->10.128.239.57:3389', 'src_ip': '91.238.181.95', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 14, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 27, 2026 11:01:05.705259000 +08'}
  - [external_access_analysis] external_sensitive_access = 185.42.12.42->10.128.239.57:3389 (score=0.90) details={'entity': '185.42.12.42->10.128.239.57:3389', 'src_ip': '185.42.12.42', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 7, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 27, 2026 11:01:05.735813000 +08'}
  - [external_access_analysis] external_sensitive_access = 179.60.146.36->10.128.239.57:3389 (score=0.90) details={'entity': '179.60.146.36->10.128.239.57:3389', 'src_ip': '179.60.146.36', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 16, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 27, 2026 11:01:05.859878000 +08'}
  - [external_access_analysis] external_sensitive_access = 141.98.11.8->10.128.239.57:3389 (score=0.80) details={'entity': '141.98.11.8->10.128.239.57:3389', 'src_ip': '141.98.11.8', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Jan 27, 2026 11:01:05.953962000 +08'}
  - [external_access_analysis] external_sensitive_access = 91.238.181.7->10.128.239.57:3389 (score=0.90) details={'entity': '91.238.181.7->10.128.239.57:3389', 'src_ip': '91.238.181.7', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 8, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 27, 2026 11:01:06.565918000 +08'}
  - [external_access_analysis] external_sensitive_access = 179.60.146.37->10.128.239.57:3389 (score=0.90) details={'entity': '179.60.146.37->10.128.239.57:3389', 'src_ip': '179.60.146.37', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 8, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 27, 2026 18:00:37.870290000 +08'}
  - [external_access_analysis] external_sensitive_access = 80.75.212.32->10.128.239.57:3389 (score=0.90) details={'entity': '80.75.212.32->10.128.239.57:3389', 'src_ip': '80.75.212.32', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 7, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 27, 2026 18:00:37.966832000 +08'}
  - [external_access_analysis] external_sensitive_access = 91.238.181.10->10.128.239.57:3389 (score=0.90) details={'entity': '91.238.181.10->10.128.239.57:3389', 'src_ip': '91.238.181.10', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 27, 2026 18:00:38.058401000 +08'}
  - [external_access_analysis] external_sensitive_access = 80.91.223.58->10.128.239.57:3389 (score=0.90) details={'entity': '80.91.223.58->10.128.239.57:3389', 'src_ip': '80.91.223.58', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 7, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 27, 2026 18:00:38.089476000 +08'}
  - [external_access_analysis] external_sensitive_access = 88.214.25.121->10.128.239.57:3389 (score=0.90) details={'entity': '88.214.25.121->10.128.239.57:3389', 'src_ip': '88.214.25.121', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 27, 2026 18:00:38.283691000 +08'}
  - [external_access_analysis] external_sensitive_access = 141.98.83.70->10.128.239.57:3389 (score=0.80) details={'entity': '141.98.83.70->10.128.239.57:3389', 'src_ip': '141.98.83.70', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Jan 27, 2026 18:00:38.572134000 +08'}
  - [external_access_analysis] external_sensitive_access = 179.60.146.33->10.128.239.57:3389 (score=0.90) details={'entity': '179.60.146.33->10.128.239.57:3389', 'src_ip': '179.60.146.33', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 17, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 27, 2026 21:59:59.380978000 +08'}
  - [external_access_analysis] external_sensitive_access = 103.180.176.136->10.128.239.57:3389 (score=0.90) details={'entity': '103.180.176.136->10.128.239.57:3389', 'src_ip': '103.180.176.136', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 11, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 27, 2026 21:59:59.843681000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.83**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->91.238.181.95:5484, 10.128.239.57->179.60.146.36:54168, 10.128.239.57->179.60.146.36:53742, 10.128.239.57->91.238.181.7:38080, 10.128.239.57->185.42.12.42:36653, 10.128.239.57->179.60.146.37:65315, 10.128.239.57->88.214.25.121:29514, 10.128.239.57->80.75.212.32:39007, 10.128.239.57->179.60.146.33:54973, 10.128.239.57->103.180.176.136:15683
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.95:5484 (score=0.60) details={'entity': '10.128.239.57->91.238.181.95:5484', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.95', 'dst_port': 5484, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 11:01:05.829064000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.36:54168 (score=0.60) details={'entity': '10.128.239.57->179.60.146.36:54168', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'dst_port': 54168, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 11:01:05.923910000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.36:53742 (score=0.60) details={'entity': '10.128.239.57->179.60.146.36:53742', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'dst_port': 53742, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 11:01:06.195785000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.36:54168 (score=0.60) details={'entity': '10.128.239.57->179.60.146.36:54168', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'dst_port': 54168, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 11:01:06.265301000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.95:5484 (score=0.60) details={'entity': '10.128.239.57->91.238.181.95:5484', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.95', 'dst_port': 5484, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 11:01:06.333284000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.7:38080 (score=0.60) details={'entity': '10.128.239.57->91.238.181.7:38080', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.7', 'dst_port': 38080, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 11:01:06.365241000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->185.42.12.42:36653 (score=0.60) details={'entity': '10.128.239.57->185.42.12.42:36653', 'src_ip': '10.128.239.57', 'dst_ip': '185.42.12.42', 'dst_port': 36653, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 11:01:06.427613000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.36:54168 (score=0.60) details={'entity': '10.128.239.57->179.60.146.36:54168', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'dst_port': 54168, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 11:01:06.532722000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.37:65315 (score=0.60) details={'entity': '10.128.239.57->179.60.146.37:65315', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.37', 'dst_port': 65315, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 18:00:37.934715000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->88.214.25.121:29514 (score=0.60) details={'entity': '10.128.239.57->88.214.25.121:29514', 'src_ip': '10.128.239.57', 'dst_ip': '88.214.25.121', 'dst_port': 29514, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 18:00:38.316600000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->80.75.212.32:39007 (score=0.60) details={'entity': '10.128.239.57->80.75.212.32:39007', 'src_ip': '10.128.239.57', 'dst_ip': '80.75.212.32', 'dst_port': 39007, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 18:00:38.540715000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.33:54973 (score=0.60) details={'entity': '10.128.239.57->179.60.146.33:54973', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.33', 'dst_port': 54973, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 21:59:59.445202000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->103.180.176.136:15683 (score=0.60) details={'entity': '10.128.239.57->103.180.176.136:15683', 'src_ip': '10.128.239.57', 'dst_ip': '103.180.176.136', 'dst_port': 15683, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 21:59:59.909083000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.33:54973 (score=0.60) details={'entity': '10.128.239.57->179.60.146.33:54973', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.33', 'dst_port': 54973, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 21:59:59.979364000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.33:54973 (score=0.60) details={'entity': '10.128.239.57->179.60.146.33:54973', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.33', 'dst_port': 54973, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 22:00:00.142615000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->103.180.176.136:15683 (score=0.60) details={'entity': '10.128.239.57->103.180.176.136:15683', 'src_ip': '10.128.239.57', 'dst_ip': '103.180.176.136', 'dst_port': 15683, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 16, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 27, 2026 22:00:00.292031000 +08'}

### 3. Potential Data Exfiltration
- Severity: **HIGH**
- Confidence: **0.68**
- MITRE ATT&CK: T1048, T1041, T1567
- Description: Large or frequent outbound transfers to external host suggest data exfiltration.
- Recommendation: Block the destination IP, isolate the source host, and forensically examine what data may have been transferred.
- Affected Entities: 10.128.239.57->185.42.12.42, 10.128.239.57->91.238.181.95, 10.128.239.57->179.60.146.36, 10.128.239.57->91.238.181.7, 10.128.239.57->80.75.212.32, 10.128.239.57->179.60.146.33, 10.128.239.21->13.107.222.240, 10.128.239.57->103.180.176.136
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
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->185.42.12.42 (score=0.40) details={'entity': '10.128.239.57->185.42.12.42', 'src_ip': '10.128.239.57', 'dst_ip': '185.42.12.42', 'session_count': 5, 'total_bytes': 0, 'ports_used': [36653], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Jan 27, 2026 11:01:05.766429000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->91.238.181.95 (score=0.30) details={'entity': '10.128.239.57->91.238.181.95', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.95', 'session_count': 6, 'total_bytes': 0, 'ports_used': [5484], 'reasons': ['high_session_count'], 'event_timestamp': 'Jan 27, 2026 11:01:05.829064000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->179.60.146.36 (score=0.60) details={'entity': '10.128.239.57->179.60.146.36', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'session_count': 12, 'total_bytes': 0, 'ports_used': [53742, 54168], 'reasons': ['high_session_count', 'very_high_session_count', 'high_port_usage'], 'event_timestamp': 'Jan 27, 2026 11:01:05.923910000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->91.238.181.7 (score=0.40) details={'entity': '10.128.239.57->91.238.181.7', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.7', 'session_count': 5, 'total_bytes': 0, 'ports_used': [38080], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Jan 27, 2026 11:01:06.365241000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->80.75.212.32 (score=0.40) details={'entity': '10.128.239.57->80.75.212.32', 'src_ip': '10.128.239.57', 'dst_ip': '80.75.212.32', 'session_count': 5, 'total_bytes': 0, 'ports_used': [39007], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Jan 27, 2026 18:00:37.998623000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->179.60.146.33 (score=0.60) details={'entity': '10.128.239.57->179.60.146.33', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.33', 'session_count': 11, 'total_bytes': 0, 'ports_used': [54973], 'reasons': ['high_session_count', 'very_high_session_count', 'high_port_usage'], 'event_timestamp': 'Jan 27, 2026 21:59:59.445202000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.21->13.107.222.240 (score=0.30) details={'entity': '10.128.239.21->13.107.222.240', 'src_ip': '10.128.239.21', 'dst_ip': '13.107.222.240', 'session_count': 6, 'total_bytes': 0, 'ports_used': [53], 'reasons': ['high_session_count'], 'event_timestamp': 'Jan 27, 2026 21:59:59.542357000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->103.180.176.136 (score=0.40) details={'entity': '10.128.239.57->103.180.176.136', 'src_ip': '10.128.239.57', 'dst_ip': '103.180.176.136', 'session_count': 6, 'total_bytes': 0, 'ports_used': [15683], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Jan 27, 2026 21:59:59.909083000 +08'}

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

- 2026-04-16T18:55:07.036088Z | review_summary | Started summary-first investigation
- 2026-04-16T18:55:07.039543Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-16T18:55:07.039595Z | analyze_dns | Completed DNS analysis
- 2026-04-16T18:55:07.039598Z | analyze_http | Completed HTTP analysis
- 2026-04-16T18:55:07.039710Z | analyze_tls | Completed TLS analysis
- 2026-04-16T18:55:07.039730Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-16T18:55:07.039785Z | analyze_smb | Completed SMB analysis
- 2026-04-16T18:55:07.040085Z | analyze_external_access | Completed external access analysis
- 2026-04-16T18:55:07.040547Z | analyze_volumetric | Completed volumetric analysis
- 2026-04-16T18:55:07.040580Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-16T18:55:07.040620Z | materialize_findings | Generated 3 final findings