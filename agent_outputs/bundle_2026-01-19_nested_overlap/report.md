# Agentic Network Forensic Report — bundle_2026-01-19_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-19_nested_overlap` and identified **2 reportable finding(s)**. The highest-confidence finding was **External Sensitive Access** with confidence **1.00** and severity **HIGH**.

## Analysis Metrics

- Event Count: 182
- PCAP Count: 4
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
- Affected Entities: 194.165.17.11->10.128.239.57:3389, 136.144.43.111->10.128.239.57:3389, 80.75.212.45->10.128.239.57:3389, 185.147.125.31->10.128.239.57:3389, 141.98.83.10->10.128.239.57:3389, 45.141.87.201->10.128.239.57:3389
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
  - [external_access_analysis] external_sensitive_access = 194.165.17.11->10.128.239.57:3389 (score=0.90) details={'entity': '194.165.17.11->10.128.239.57:3389', 'src_ip': '194.165.17.11', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 10, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 19, 2026 01:09:43.832354000 +08'}
  - [external_access_analysis] external_sensitive_access = 136.144.43.111->10.128.239.57:3389 (score=0.80) details={'entity': '136.144.43.111->10.128.239.57:3389', 'src_ip': '136.144.43.111', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Jan 19, 2026 01:09:44.098250000 +08'}
  - [external_access_analysis] external_sensitive_access = 80.75.212.45->10.128.239.57:3389 (score=0.90) details={'entity': '80.75.212.45->10.128.239.57:3389', 'src_ip': '80.75.212.45', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 10, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 19, 2026 04:17:19.486891000 +08'}
  - [external_access_analysis] external_sensitive_access = 185.147.125.31->10.128.239.57:3389 (score=0.90) details={'entity': '185.147.125.31->10.128.239.57:3389', 'src_ip': '185.147.125.31', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 7, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 19, 2026 04:17:19.609830000 +08'}
  - [external_access_analysis] external_sensitive_access = 141.98.83.10->10.128.239.57:3389 (score=0.80) details={'entity': '141.98.83.10->10.128.239.57:3389', 'src_ip': '141.98.83.10', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Jan 19, 2026 23:50:55.966326000 +08'}
  - [external_access_analysis] external_sensitive_access = 45.141.87.201->10.128.239.57:3389 (score=0.90) details={'entity': '45.141.87.201->10.128.239.57:3389', 'src_ip': '45.141.87.201', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 19, 2026 23:50:56.027422000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.83**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->136.144.43.111:33138, 10.128.239.57->80.75.212.45:55110, 10.128.239.57->185.147.125.31:23480, 10.128.239.57->45.130.145.78:35445, 10.128.239.57->141.98.83.10:57148, 10.128.239.57->45.141.87.201:38772
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->136.144.43.111:33138 (score=0.60) details={'entity': '10.128.239.57->136.144.43.111:33138', 'src_ip': '10.128.239.57', 'dst_ip': '136.144.43.111', 'dst_port': 33138, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 19, 2026 01:09:44.067631000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->80.75.212.45:55110 (score=0.60) details={'entity': '10.128.239.57->80.75.212.45:55110', 'src_ip': '10.128.239.57', 'dst_ip': '80.75.212.45', 'dst_port': 55110, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 19, 2026 04:17:19.974029000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->185.147.125.31:23480 (score=0.60) details={'entity': '10.128.239.57->185.147.125.31:23480', 'src_ip': '10.128.239.57', 'dst_ip': '185.147.125.31', 'dst_port': 23480, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 19, 2026 04:17:20.306312000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.130.145.78:35445 (score=0.60) details={'entity': '10.128.239.57->45.130.145.78:35445', 'src_ip': '10.128.239.57', 'dst_ip': '45.130.145.78', 'dst_port': 35445, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 19, 2026 04:17:20.373796000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.83.10:57148 (score=0.60) details={'entity': '10.128.239.57->141.98.83.10:57148', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.83.10', 'dst_port': 57148, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 19, 2026 23:50:55.714692000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.141.87.201:38772 (score=0.60) details={'entity': '10.128.239.57->45.141.87.201:38772', 'src_ip': '10.128.239.57', 'dst_ip': '45.141.87.201', 'dst_port': 38772, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 19, 2026 23:50:55.908799000 +08'}

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

- 2026-04-16T18:55:06.984422Z | review_summary | Started summary-first investigation
- 2026-04-16T18:55:06.986717Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-16T18:55:06.986831Z | analyze_dns | Completed DNS analysis
- 2026-04-16T18:55:06.986833Z | analyze_http | Completed HTTP analysis
- 2026-04-16T18:55:06.986878Z | analyze_tls | Completed TLS analysis
- 2026-04-16T18:55:06.986892Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-16T18:55:06.986929Z | analyze_smb | Completed SMB analysis
- 2026-04-16T18:55:06.987053Z | analyze_external_access | Completed external access analysis
- 2026-04-16T18:55:06.987296Z | analyze_volumetric | Completed volumetric analysis
- 2026-04-16T18:55:06.987313Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-16T18:55:06.987343Z | materialize_findings | Generated 2 final findings