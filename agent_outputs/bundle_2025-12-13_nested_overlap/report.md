# Agentic Network Forensic Report — bundle_2025-12-13_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2025-12-13_nested_overlap` and identified **1 reportable finding(s)**. The highest-confidence finding was **External Sensitive Access** with confidence **1.00** and severity **HIGH**.

## Analysis Metrics

- Event Count: 130
- PCAP Count: 4
- Hypothesis Count: 1
- Finding Count: 1
- Analysis Runtime (seconds): 0.002
- Estimated Analysis Cost: 0.0
- Human Review Required Count: 0
- Guardrailed Hypothesis Count: 1

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
- Affected Entities: 147.45.112.183->10.128.239.57:3389, 88.214.25.115->10.128.239.57:3389, 179.60.146.37->10.128.239.57:3389, 141.98.11.49->10.128.239.57:3389, 181.49.207.198->10.128.239.57:3389, 150.242.202.185->10.128.239.57:3389
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
  - [external_access_analysis] external_sensitive_access = 147.45.112.183->10.128.239.57:3389 (score=0.80) details={'entity': '147.45.112.183->10.128.239.57:3389', 'src_ip': '147.45.112.183', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Dec 13, 2025 12:01:08.202922000 +08'}
  - [external_access_analysis] external_sensitive_access = 88.214.25.115->10.128.239.57:3389 (score=0.90) details={'entity': '88.214.25.115->10.128.239.57:3389', 'src_ip': '88.214.25.115', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 5, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 13, 2025 12:16:21.219347000 +08'}
  - [external_access_analysis] external_sensitive_access = 179.60.146.37->10.128.239.57:3389 (score=0.80) details={'entity': '179.60.146.37->10.128.239.57:3389', 'src_ip': '179.60.146.37', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Dec 13, 2025 12:31:13.753931000 +08'}
  - [external_access_analysis] external_sensitive_access = 141.98.11.49->10.128.239.57:3389 (score=0.80) details={'entity': '141.98.11.49->10.128.239.57:3389', 'src_ip': '141.98.11.49', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Dec 13, 2025 12:31:13.864511000 +08'}
  - [external_access_analysis] external_sensitive_access = 181.49.207.198->10.128.239.57:3389 (score=0.90) details={'entity': '181.49.207.198->10.128.239.57:3389', 'src_ip': '181.49.207.198', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Dec 13, 2025 12:31:13.989346000 +08'}
  - [external_access_analysis] external_sensitive_access = 150.242.202.185->10.128.239.57:3389 (score=0.80) details={'entity': '150.242.202.185->10.128.239.57:3389', 'src_ip': '150.242.202.185', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 2, 'reasons': ['external_rdp_access', 'external_rdp_inbound'], 'event_timestamp': 'Dec 13, 2025 12:31:14.109124000 +08'}

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

- 2026-04-16T18:55:06.775274Z | review_summary | Started summary-first investigation
- 2026-04-16T18:55:06.776941Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-16T18:55:06.776951Z | analyze_dns | Completed DNS analysis
- 2026-04-16T18:55:06.776953Z | analyze_http | Completed HTTP analysis
- 2026-04-16T18:55:06.776966Z | analyze_tls | Completed TLS analysis
- 2026-04-16T18:55:06.776977Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-16T18:55:06.777008Z | analyze_smb | Completed SMB analysis
- 2026-04-16T18:55:06.777090Z | analyze_external_access | Completed external access analysis
- 2026-04-16T18:55:06.777219Z | analyze_volumetric | Completed volumetric analysis
- 2026-04-16T18:55:06.777227Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-16T18:55:06.777244Z | materialize_findings | Generated 1 final findings