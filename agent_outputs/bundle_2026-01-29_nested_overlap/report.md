# Agentic Network Forensic Report — bundle_2026-01-29_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-29_nested_overlap` and identified **3 reportable finding(s)**. The highest-confidence finding was **External Sensitive Access** with confidence **1.00** and severity **HIGH**.

## Analysis Metrics

- Event Count: 128
- PCAP Count: 2
- Hypothesis Count: 4
- Finding Count: 3
- Analysis Runtime (seconds): 0.002
- Estimated Analysis Cost: 0.0
- Human Review Required Count: 1
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
- Affected Entities: 210.19.252.30->10.128.239.57:3389, 45.130.145.9->10.128.239.57:3389, 194.165.17.11->10.128.239.57:3389, 91.238.181.7->10.128.239.57:3389, 88.214.25.115->10.128.239.57:3389
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
  - [external_access_analysis] external_sensitive_access = 210.19.252.30->10.128.239.57:3389 (score=0.90) details={'entity': '210.19.252.30->10.128.239.57:3389', 'src_ip': '210.19.252.30', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 29, 2026 00:08:08.936553000 +08'}
  - [external_access_analysis] external_sensitive_access = 45.130.145.9->10.128.239.57:3389 (score=0.80) details={'entity': '45.130.145.9->10.128.239.57:3389', 'src_ip': '45.130.145.9', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Jan 29, 2026 00:08:09.626006000 +08'}
  - [external_access_analysis] external_sensitive_access = 194.165.17.11->10.128.239.57:3389 (score=0.90) details={'entity': '194.165.17.11->10.128.239.57:3389', 'src_ip': '194.165.17.11', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 29, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 29, 2026 14:18:52.330918000 +08'}
  - [external_access_analysis] external_sensitive_access = 91.238.181.7->10.128.239.57:3389 (score=0.90) details={'entity': '91.238.181.7->10.128.239.57:3389', 'src_ip': '91.238.181.7', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 10, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 29, 2026 14:18:52.905171000 +08'}
  - [external_access_analysis] external_sensitive_access = 88.214.25.115->10.128.239.57:3389 (score=0.90) details={'entity': '88.214.25.115->10.128.239.57:3389', 'src_ip': '88.214.25.115', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 4, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 29, 2026 14:18:53.172577000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.78**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->194.165.17.11:40280, 10.128.239.57->91.238.181.7:47120
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->194.165.17.11:40280 (score=0.60) details={'entity': '10.128.239.57->194.165.17.11:40280', 'src_ip': '10.128.239.57', 'dst_ip': '194.165.17.11', 'dst_port': 40280, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 29, 2026 14:18:52.609052000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.7:47120 (score=0.60) details={'entity': '10.128.239.57->91.238.181.7:47120', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.7', 'dst_port': 47120, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 29, 2026 14:18:52.729345000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->194.165.17.11:40280 (score=0.60) details={'entity': '10.128.239.57->194.165.17.11:40280', 'src_ip': '10.128.239.57', 'dst_ip': '194.165.17.11', 'dst_port': 40280, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 29, 2026 14:18:52.797676000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->194.165.17.11:40280 (score=0.60) details={'entity': '10.128.239.57->194.165.17.11:40280', 'src_ip': '10.128.239.57', 'dst_ip': '194.165.17.11', 'dst_port': 40280, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 29, 2026 14:18:52.872623000 +08'}

### 3. Potential Data Exfiltration
- Severity: **HIGH**
- Confidence: **0.60**
- MITRE ATT&CK: T1048, T1041, T1567
- Description: Large or frequent outbound transfers to external host suggest data exfiltration.
- Recommendation: Block the destination IP, isolate the source host, and forensically examine what data may have been transferred.
- Affected Entities: 10.128.239.57->194.165.17.11, 10.128.239.57->91.238.181.7
- Human Review Required: Yes
- Guardrail Flags: limited_source_diversity, reportable_but_thin_evidence
- False Positive Risks:
  - Large legitimate uploads (backups, cloud sync, CI/CD) may trigger volumetric thresholds.
- Missed Detection Risks:
  - Slow, low-volume exfiltration may stay below detection thresholds.
  - Encrypted exfiltration via legitimate services may not be flagged.
- Technical Limitations:
  - Volumetric analysis detects transfer patterns, not content — payload inspection requires decryption.
- Evidence:
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->194.165.17.11 (score=0.60) details={'entity': '10.128.239.57->194.165.17.11', 'src_ip': '10.128.239.57', 'dst_ip': '194.165.17.11', 'session_count': 15, 'total_bytes': 0, 'ports_used': [30559, 40280], 'reasons': ['high_session_count', 'very_high_session_count', 'high_port_usage'], 'event_timestamp': 'Jan 29, 2026 14:18:52.454427000 +08'}
  - [volumetric_analysis] volumetric_anomaly = 10.128.239.57->91.238.181.7 (score=0.40) details={'entity': '10.128.239.57->91.238.181.7', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.7', 'session_count': 5, 'total_bytes': 0, 'ports_used': [47120], 'reasons': ['high_session_count', 'high_port_usage'], 'event_timestamp': 'Jan 29, 2026 14:18:52.729345000 +08'}

## Analyst Validation Notes

The following findings should be validated by a human analyst before containment or attribution decisions:
- Potential Data Exfiltration (confidence=0.60, flags=limited_source_diversity, reportable_but_thin_evidence)

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

- 2026-04-16T18:55:07.055010Z | review_summary | Started summary-first investigation
- 2026-04-16T18:55:07.056874Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-16T18:55:07.056884Z | analyze_dns | Completed DNS analysis
- 2026-04-16T18:55:07.056886Z | analyze_http | Completed HTTP analysis
- 2026-04-16T18:55:07.056930Z | analyze_tls | Completed TLS analysis
- 2026-04-16T18:55:07.056941Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-16T18:55:07.056978Z | analyze_smb | Completed SMB analysis
- 2026-04-16T18:55:07.057118Z | analyze_external_access | Completed external access analysis
- 2026-04-16T18:55:07.057302Z | analyze_volumetric | Completed volumetric analysis
- 2026-04-16T18:55:07.057317Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-16T18:55:07.057349Z | materialize_findings | Generated 3 final findings