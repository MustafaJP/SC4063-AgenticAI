# Agentic Network Forensic Report — bundle_2025-12-19_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2025-12-19_nested_overlap` and identified **4 reportable finding(s)**. The highest-confidence finding was **Known Bad IP Communication** with confidence **1.00** and severity **HIGH**.

## Analysis Metrics

- Event Count: 143
- PCAP Count: 4
- Hypothesis Count: 5
- Finding Count: 4
- Analysis Runtime (seconds): 0.002
- Estimated Analysis Cost: 0.0
- Human Review Required Count: 1
- Guardrailed Hypothesis Count: 5

## Safety Controls and Guardrails

- **minimum_evidence_requirement**: Hypotheses with fewer than 2 evidence items are downgraded below formal reporting threshold.
- **confidence_threshold_for_reporting**: Only hypotheses with confidence >= 0.6 are materialized as findings.
- **human_review_for_high_impact_or_thin_claims**: Potentially high-impact findings and thinly corroborated claims are flagged for analyst validation before operational use.
- **source_diversity_tracking**: Hypotheses record whether evidence came from limited or multiple analytic sources.

## Findings

### 1. Known Bad IP Communication
- Severity: **HIGH**
- Confidence: **1.00**
- MITRE ATT&CK: T1071, T1105
- Description: Communication with reputation-flagged IP suggests malicious or risky external contact.
- Recommendation: Block the destination IP immediately and perform retrospective searches across related logs and endpoints.
- Affected Entities: 51.91.79.17
- Human Review Required: Yes
- Guardrail Flags: limited_source_diversity, high_impact_claim_requires_human_validation
- False Positive Risks:
  - Threat intelligence feeds may be stale, noisy, or context-dependent.
- Missed Detection Risks:
  - Malicious infrastructure not present in the configured bad-IP list will not be caught by reputation alone.
- Technical Limitations:
  - IP reputation is only as strong as the configured intelligence source and update cadence.
- Evidence:
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:39.473619000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:39.473619000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:39.473619000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:39.609284000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:39.609284000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:39.609284000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:39.753587000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:39.753587000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:39.753587000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:39.888964000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:39.888964000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:39.888964000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:40.037642000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:40.037642000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:40.037642000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:40.175086000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:40.175086000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:40.175086000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:40.311238000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:40.311238000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:40.311238000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:40.448704000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:40.448704000 +08'}
  - [intel_analysis] bad_reputation_ip = 51.91.79.17 (score=0.95) details={'entity': '51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'dst_port': 443, 'proto': 'tcp', 'event_timestamp': 'Dec 19, 2025 02:50:40.448704000 +08'}

### 2. External Sensitive Access
- Severity: **HIGH**
- Confidence: **1.00**
- MITRE ATT&CK: T1133, T1078, T1021.001
- Description: External IP accessed internal host on sensitive port, suggesting unauthorized remote access.
- Recommendation: Verify authorization of external access, reset credentials on accessed hosts, and review for signs of post-exploitation activity.
- Affected Entities: 91.238.181.7->10.128.239.57:3389, 193.111.248.57->10.128.239.57:3389, 194.165.17.11->10.128.239.57:3389, 138.199.59.143->10.128.239.57:3389, 88.214.25.123->10.128.239.57:3389
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
  - [external_access_analysis] external_sensitive_access = 91.238.181.7->10.128.239.57:3389 (score=0.90) details={'entity': '91.238.181.7->10.128.239.57:3389', 'src_ip': '91.238.181.7', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 9, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 19, 2025 02:35:42.877366000 +08'}
  - [external_access_analysis] external_sensitive_access = 193.111.248.57->10.128.239.57:3389 (score=0.90) details={'entity': '193.111.248.57->10.128.239.57:3389', 'src_ip': '193.111.248.57', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 11, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 19, 2025 02:35:43.030565000 +08'}
  - [external_access_analysis] external_sensitive_access = 194.165.17.11->10.128.239.57:3389 (score=0.90) details={'entity': '194.165.17.11->10.128.239.57:3389', 'src_ip': '194.165.17.11', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 19, 2025 02:45:50.509238000 +08'}
  - [external_access_analysis] external_sensitive_access = 138.199.59.143->10.128.239.57:3389 (score=0.90) details={'entity': '138.199.59.143->10.128.239.57:3389', 'src_ip': '138.199.59.143', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 19, 2025 02:45:50.577737000 +08'}
  - [external_access_analysis] external_sensitive_access = 88.214.25.123->10.128.239.57:3389 (score=0.90) details={'entity': '88.214.25.123->10.128.239.57:3389', 'src_ip': '88.214.25.123', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 10, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 19, 2025 02:45:50.700238000 +08'}

### 3. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.83**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->193.111.248.57:43765, 10.128.239.57->91.238.181.7:38303, 10.128.239.57->194.165.17.11:53520, 10.128.239.57->138.199.59.143:32188
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->193.111.248.57:43765 (score=0.60) details={'entity': '10.128.239.57->193.111.248.57:43765', 'src_ip': '10.128.239.57', 'dst_ip': '193.111.248.57', 'dst_port': 43765, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 19, 2025 02:35:43.145391000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.7:38303 (score=0.60) details={'entity': '10.128.239.57->91.238.181.7:38303', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.7', 'dst_port': 38303, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 19, 2025 02:35:43.436848000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->193.111.248.57:43765 (score=0.60) details={'entity': '10.128.239.57->193.111.248.57:43765', 'src_ip': '10.128.239.57', 'dst_ip': '193.111.248.57', 'dst_port': 43765, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 19, 2025 02:35:43.812274000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->194.165.17.11:53520 (score=0.60) details={'entity': '10.128.239.57->194.165.17.11:53520', 'src_ip': '10.128.239.57', 'dst_ip': '194.165.17.11', 'dst_port': 53520, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 19, 2025 02:45:50.637957000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->138.199.59.143:32188 (score=0.60) details={'entity': '10.128.239.57->138.199.59.143:32188', 'src_ip': '10.128.239.57', 'dst_ip': '138.199.59.143', 'dst_port': 32188, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 19, 2025 02:45:50.931466000 +08'}

### 4. Potential Data Exfiltration
- Severity: **HIGH**
- Confidence: **0.65**
- MITRE ATT&CK: T1048, T1041, T1567
- Description: Large or frequent outbound transfers to external host suggest data exfiltration.
- Recommendation: Block the destination IP, isolate the source host, and forensically examine what data may have been transferred.
- Affected Entities: 10.128.239.57->193.111.248.57, 10.128.239.21->199.19.56.1, 10.128.239.57->51.91.79.17
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
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->193.111.248.57 (score=0.40) details={'entity': '10.128.239.57->193.111.248.57', 'src_ip': '10.128.239.57', 'dst_ip': '193.111.248.57', 'session_count': 6, 'total_bytes': 0, 'ports_used': [43765], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Dec 19, 2025 02:35:43.145391000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.21->199.19.56.1 (score=0.30) details={'entity': '10.128.239.21->199.19.56.1', 'src_ip': '10.128.239.21', 'dst_ip': '199.19.56.1', 'session_count': 6, 'total_bytes': 0, 'ports_used': [53], 'reasons': ['high_session_count'], 'event_timestamp': 'Dec 19, 2025 02:45:50.440468000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->51.91.79.17 (score=0.80) details={'entity': '10.128.239.57->51.91.79.17', 'src_ip': '10.128.239.57', 'dst_ip': '51.91.79.17', 'session_count': 24, 'total_bytes': 0, 'ports_used': [443], 'reasons': ['high_session_count', 'very_high_session_count', 'excessive_sessions', 'https_exfil_channel'], 'event_timestamp': 'Dec 19, 2025 02:50:39.473619000 +08'}

## Analyst Validation Notes

The following findings should be validated by a human analyst before containment or attribution decisions:
- Known Bad IP Communication (confidence=1.00, flags=limited_source_diversity, high_impact_claim_requires_human_validation)

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

- 2026-04-16T18:55:06.823826Z | review_summary | Started summary-first investigation
- 2026-04-16T18:55:06.825653Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-16T18:55:06.825740Z | analyze_dns | Completed DNS analysis
- 2026-04-16T18:55:06.825742Z | analyze_http | Completed HTTP analysis
- 2026-04-16T18:55:06.825801Z | analyze_tls | Completed TLS analysis
- 2026-04-16T18:55:06.825846Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-16T18:55:06.825876Z | analyze_smb | Completed SMB analysis
- 2026-04-16T18:55:06.825993Z | analyze_external_access | Completed external access analysis
- 2026-04-16T18:55:06.826237Z | analyze_volumetric | Completed volumetric analysis
- 2026-04-16T18:55:06.826263Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-16T18:55:06.826302Z | materialize_findings | Generated 4 final findings