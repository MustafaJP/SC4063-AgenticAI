# Agentic Network Forensic Report — bundle_2026-01-15_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-15_nested_overlap` and identified **1 reportable finding(s)**. The highest-confidence finding was **External Sensitive Access** with confidence **1.00** and severity **HIGH**.

## Analysis Metrics

- Event Count: 27
- PCAP Count: 1
- Hypothesis Count: 1
- Finding Count: 1
- Analysis Runtime (seconds): 0.001
- Estimated Analysis Cost: 0.0
- Human Review Required Count: 1
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
- Affected Entities: 179.60.146.32->10.128.239.57:3389, 91.238.181.10->10.128.239.57:3389
- Human Review Required: Yes
- Guardrail Flags: limited_source_diversity, reportable_but_thin_evidence
- False Positive Risks:
  - Legitimate remote administration via RDP or SSH from authorized external IPs.
  - VPN or jump-host traffic may appear as external access.
- Missed Detection Risks:
  - Access via VPN tunnels that terminate internally will not appear as external.
- Technical Limitations:
  - Cannot distinguish between authorized and unauthorized remote access without credential context.
- Evidence:
  - [external_access_analysis] external_sensitive_access = 179.60.146.32->10.128.239.57:3389 (score=0.90) details={'entity': '179.60.146.32->10.128.239.57:3389', 'src_ip': '179.60.146.32', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 15, 2026 15:06:11.737376000 +08'}
  - [external_access_analysis] external_sensitive_access = 91.238.181.10->10.128.239.57:3389 (score=0.90) details={'entity': '91.238.181.10->10.128.239.57:3389', 'src_ip': '91.238.181.10', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'service': 'RDP', 'connection_count': 3, 'reasons': ['external_rdp_access', 'external_rdp_inbound', 'repeated_access'], 'event_timestamp': 'Jan 15, 2026 15:06:12.184728000 +08'}

## Analyst Validation Notes

The following findings should be validated by a human analyst before containment or attribution decisions:
- External Sensitive Access (confidence=1.00, flags=limited_source_diversity, reportable_but_thin_evidence)

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

- 2026-04-16T18:55:06.958406Z | review_summary | Started summary-first investigation
- 2026-04-16T18:55:06.958959Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-16T18:55:06.958969Z | analyze_dns | Completed DNS analysis
- 2026-04-16T18:55:06.958971Z | analyze_http | Completed HTTP analysis
- 2026-04-16T18:55:06.958985Z | analyze_tls | Completed TLS analysis
- 2026-04-16T18:55:06.958989Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-16T18:55:06.958998Z | analyze_smb | Completed SMB analysis
- 2026-04-16T18:55:06.959041Z | analyze_external_access | Completed external access analysis
- 2026-04-16T18:55:06.959086Z | analyze_volumetric | Completed volumetric analysis
- 2026-04-16T18:55:06.959092Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-16T18:55:06.959112Z | materialize_findings | Generated 1 final findings