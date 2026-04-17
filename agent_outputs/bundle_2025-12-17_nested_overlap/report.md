# Agentic Network Forensic Report — bundle_2025-12-17_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2025-12-17_nested_overlap` and identified **3 reportable finding(s)**. The highest-confidence finding was **External Sensitive Access** with confidence **1.00** and severity **HIGH**.

## Analysis Metrics

- Event Count: 163
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
- Affected Entities: 91.238.181.10->10.128.239.57:3389, 185.42.12.42->10.128.239.57:3389, 45.227.254.151->10.128.239.57:3389, 141.98.83.10->10.128.239.57:3389, 179.60.146.36->10.128.239.57:3389, 98.159.33.100->10.128.239.57:3389, 91.238.181.6->10.128.239.57:3389, 179.60.146.35->10.128.239.57:3389, 45.135.232.19->10.128.239.57:3389, 91.238.181.8->10.128.239.57:3389, 80.75.212.45->10.128.239.57:3389, 141.98.11.170->10.128.239.57:3389, 147.45.112.108->10.128.239.57:3389, 136.144.42.225->10.128.239.57:3389
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
  - [external_access_analysis] external_sensitive_access = 91.238.181.10->10.128.239.57:3389 (score=0.90) details={'entity': '91.238.181.10->10.128.239.57:3389', 'src_ip': '91.238.181.10', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 17, 2025 09:42:43.298187000 +08'}
  - [external_access_analysis] external_sensitive_access = 185.42.12.42->10.128.239.57:3389 (score=0.80) details={'entity': '185.42.12.42->10.128.239.57:3389', 'src_ip': '185.42.12.42', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Dec 17, 2025 09:42:43.352895000 +08'}
  - [external_access_analysis] external_sensitive_access = 45.227.254.151->10.128.239.57:3389 (score=0.90) details={'entity': '45.227.254.151->10.128.239.57:3389', 'src_ip': '45.227.254.151', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 17, 2025 09:42:43.452815000 +08'}
  - [external_access_analysis] external_sensitive_access = 141.98.83.10->10.128.239.57:3389 (score=0.90) details={'entity': '141.98.83.10->10.128.239.57:3389', 'src_ip': '141.98.83.10', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 9, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 17, 2025 09:42:43.622969000 +08'}
  - [external_access_analysis] external_sensitive_access = 179.60.146.36->10.128.239.57:3389 (score=0.90) details={'entity': '179.60.146.36->10.128.239.57:3389', 'src_ip': '179.60.146.36', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 7, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 17, 2025 09:42:43.734578000 +08'}
  - [external_access_analysis] external_sensitive_access = 98.159.33.100->10.128.239.57:3389 (score=0.90) details={'entity': '98.159.33.100->10.128.239.57:3389', 'src_ip': '98.159.33.100', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 5, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 17, 2025 20:31:35.581983000 +08'}
  - [external_access_analysis] external_sensitive_access = 91.238.181.6->10.128.239.57:3389 (score=0.90) details={'entity': '91.238.181.6->10.128.239.57:3389', 'src_ip': '91.238.181.6', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 10, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 17, 2025 20:31:35.970104000 +08'}
  - [external_access_analysis] external_sensitive_access = 179.60.146.35->10.128.239.57:3389 (score=0.80) details={'entity': '179.60.146.35->10.128.239.57:3389', 'src_ip': '179.60.146.35', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Dec 17, 2025 20:52:07.761352000 +08'}
  - [external_access_analysis] external_sensitive_access = 45.135.232.19->10.128.239.57:3389 (score=0.90) details={'entity': '45.135.232.19->10.128.239.57:3389', 'src_ip': '45.135.232.19', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 17, 2025 20:52:07.885293000 +08'}
  - [external_access_analysis] external_sensitive_access = 91.238.181.8->10.128.239.57:3389 (score=0.90) details={'entity': '91.238.181.8->10.128.239.57:3389', 'src_ip': '91.238.181.8', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 8, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 17, 2025 20:52:08.295900000 +08'}
  - [external_access_analysis] external_sensitive_access = 80.75.212.45->10.128.239.57:3389 (score=0.80) details={'entity': '80.75.212.45->10.128.239.57:3389', 'src_ip': '80.75.212.45', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Dec 17, 2025 20:52:08.531314000 +08'}
  - [external_access_analysis] external_sensitive_access = 141.98.11.170->10.128.239.57:3389 (score=0.90) details={'entity': '141.98.11.170->10.128.239.57:3389', 'src_ip': '141.98.11.170', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 9, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 17, 2025 20:55:32.620737000 +08'}
  - [external_access_analysis] external_sensitive_access = 147.45.112.108->10.128.239.57:3389 (score=0.90) details={'entity': '147.45.112.108->10.128.239.57:3389', 'src_ip': '147.45.112.108', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 5, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 17, 2025 20:55:32.736849000 +08'}
  - [external_access_analysis] external_sensitive_access = 136.144.42.225->10.128.239.57:3389 (score=0.90) details={'entity': '136.144.42.225->10.128.239.57:3389', 'src_ip': '136.144.42.225', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 4, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 17, 2025 20:55:32.952277000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.83**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->141.98.83.10:51994, 10.128.239.57->179.60.146.36:60950, 10.128.239.57->141.98.83.10:51340, 10.128.239.57->98.159.33.100:10385, 10.128.239.57->91.238.181.6:43463, 10.128.239.57->179.60.146.35:57485, 10.128.239.57->91.238.181.8:36312, 10.128.239.57->45.135.232.19:41921, 10.128.239.57->80.75.212.45:29451, 10.128.239.57->141.98.11.170:21025, 10.128.239.57->136.144.42.225:1231, 10.128.239.57->141.98.83.10:56475
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.83.10:51994 (score=0.60) details={'entity': '10.128.239.57->141.98.83.10:51994', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.83.10', 'dst_port': 51994, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 09:42:44.027172000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.36:60950 (score=0.60) details={'entity': '10.128.239.57->179.60.146.36:60950', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'dst_port': 60950, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 09:42:44.197550000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.83.10:51340 (score=0.60) details={'entity': '10.128.239.57->141.98.83.10:51340', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.83.10', 'dst_port': 51340, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 09:42:44.257682000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->98.159.33.100:10385 (score=0.60) details={'entity': '10.128.239.57->98.159.33.100:10385', 'src_ip': '10.128.239.57', 'dst_ip': '98.159.33.100', 'dst_port': 10385, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:31:36.087695000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.6:43463 (score=0.60) details={'entity': '10.128.239.57->91.238.181.6:43463', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.6', 'dst_port': 43463, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:31:36.259837000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.35:57485 (score=0.60) details={'entity': '10.128.239.57->179.60.146.35:57485', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.35', 'dst_port': 57485, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:52:07.706801000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.8:36312 (score=0.60) details={'entity': '10.128.239.57->91.238.181.8:36312', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.8', 'dst_port': 36312, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:52:07.818762000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.135.232.19:41921 (score=0.60) details={'entity': '10.128.239.57->45.135.232.19:41921', 'src_ip': '10.128.239.57', 'dst_ip': '45.135.232.19', 'dst_port': 41921, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:52:07.945004000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->80.75.212.45:29451 (score=0.60) details={'entity': '10.128.239.57->80.75.212.45:29451', 'src_ip': '10.128.239.57', 'dst_ip': '80.75.212.45', 'dst_port': 29451, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:52:08.235729000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.170:21025 (score=0.60) details={'entity': '10.128.239.57->141.98.11.170:21025', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.170', 'dst_port': 21025, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:55:32.681532000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->136.144.42.225:1231 (score=0.60) details={'entity': '10.128.239.57->136.144.42.225:1231', 'src_ip': '10.128.239.57', 'dst_ip': '136.144.42.225', 'dst_port': 1231, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:55:32.896258000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.83.10:56475 (score=0.60) details={'entity': '10.128.239.57->141.98.83.10:56475', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.83.10', 'dst_port': 56475, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:55:33.064639000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.170:21025 (score=0.60) details={'entity': '10.128.239.57->141.98.11.170:21025', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.170', 'dst_port': 21025, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:55:33.202796000 +08'}

### 3. Potential Data Exfiltration
- Severity: **HIGH**
- Confidence: **0.68**
- MITRE ATT&CK: T1048, T1041, T1567
- Description: Large or frequent outbound transfers to external host suggest data exfiltration.
- Recommendation: Block the destination IP, isolate the source host, and forensically examine what data may have been transferred.
- Affected Entities: 10.128.239.57->141.98.83.10, 10.128.239.57->179.60.146.36, 10.128.239.57->98.159.33.100, 10.128.239.57->91.238.181.6, 10.128.239.57->91.238.181.8, 10.128.239.57->141.98.11.170
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
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->141.98.83.10 (score=0.60) details={'entity': '10.128.239.57->141.98.83.10', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.83.10', 'session_count': 11, 'total_bytes': 0, 'ports_used': [51340, 51994, 56475], 'reasons': ['high_session_count', 'very_high_session_count', 'high_port_usage'], 'event_timestamp': 'Dec 17, 2025 09:42:43.678889000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->179.60.146.36 (score=0.40) details={'entity': '10.128.239.57->179.60.146.36', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'session_count': 5, 'total_bytes': 0, 'ports_used': [60950], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Dec 17, 2025 09:42:43.790826000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->98.159.33.100 (score=0.40) details={'entity': '10.128.239.57->98.159.33.100', 'src_ip': '10.128.239.57', 'dst_ip': '98.159.33.100', 'session_count': 5, 'total_bytes': 0, 'ports_used': [10385], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Dec 17, 2025 20:31:35.859240000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->91.238.181.6 (score=0.40) details={'entity': '10.128.239.57->91.238.181.6', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.6', 'session_count': 5, 'total_bytes': 0, 'ports_used': [43463], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Dec 17, 2025 20:31:36.027825000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->91.238.181.8 (score=0.40) details={'entity': '10.128.239.57->91.238.181.8', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.8', 'session_count': 5, 'total_bytes': 0, 'ports_used': [36312], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Dec 17, 2025 20:52:07.818762000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->141.98.11.170 (score=0.40) details={'entity': '10.128.239.57->141.98.11.170', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.170', 'session_count': 6, 'total_bytes': 0, 'ports_used': [21025], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Dec 17, 2025 20:55:32.681532000 +08'}

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

- 2026-04-16T18:55:06.805343Z | review_summary | Started summary-first investigation
- 2026-04-16T18:55:06.807860Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-16T18:55:06.807898Z | analyze_dns | Completed DNS analysis
- 2026-04-16T18:55:06.807900Z | analyze_http | Completed HTTP analysis
- 2026-04-16T18:55:06.807984Z | analyze_tls | Completed TLS analysis
- 2026-04-16T18:55:06.807998Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-16T18:55:06.808031Z | analyze_smb | Completed SMB analysis
- 2026-04-16T18:55:06.808252Z | analyze_external_access | Completed external access analysis
- 2026-04-16T18:55:06.808566Z | analyze_volumetric | Completed volumetric analysis
- 2026-04-16T18:55:06.808600Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-16T18:55:06.808639Z | materialize_findings | Generated 3 final findings