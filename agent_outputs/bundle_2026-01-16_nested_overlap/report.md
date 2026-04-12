# Agentic Network Forensic Report — bundle_2026-01-16_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-16_nested_overlap` and identified **2 reportable finding(s)**. The highest-confidence finding was **Suspicious TLS Session** with confidence **0.83** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 80
- PCAP Count: 2
- Hypothesis Count: 2
- Finding Count: 2
- Analysis Runtime (seconds): 0.0
- Estimated Analysis Cost: 0.0
- Human Review Required Count: 1
- Guardrailed Hypothesis Count: 2

## Safety Controls and Guardrails

- **minimum_evidence_requirement**: Hypotheses with fewer than 2 evidence items are downgraded below formal reporting threshold.
- **confidence_threshold_for_reporting**: Only hypotheses with confidence >= 0.6 are materialized as findings.
- **human_review_for_high_impact_or_thin_claims**: Potentially high-impact findings and thinly corroborated claims are flagged for analyst validation before operational use.
- **source_diversity_tracking**: Hypotheses record whether evidence came from limited or multiple analytic sources.

## Findings

### 1. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.83**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->179.60.146.34:55322, 10.128.239.57->141.98.11.8:23451, 10.128.239.57->194.165.16.18:56746, 10.128.239.57->92.255.85.173:38781, 179.60.146.36->10.128.239.57:3389, 10.128.239.57->179.60.146.36:52175, 10.128.239.57->147.45.112.108:56306, 210.19.252.30->10.128.239.57:3389, 10.128.239.57->210.19.252.30:61381
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.34:55322 (score=0.60) details={'entity': '10.128.239.57->179.60.146.34:55322', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.34', 'dst_port': 55322, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 16, 2026 03:22:24.422339000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.8:23451 (score=0.60) details={'entity': '10.128.239.57->141.98.11.8:23451', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.8', 'dst_port': 23451, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 16, 2026 03:22:24.562151000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->194.165.16.18:56746 (score=0.60) details={'entity': '10.128.239.57->194.165.16.18:56746', 'src_ip': '10.128.239.57', 'dst_ip': '194.165.16.18', 'dst_port': 56746, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 16, 2026 03:22:24.919683000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->92.255.85.173:38781 (score=0.60) details={'entity': '10.128.239.57->92.255.85.173:38781', 'src_ip': '10.128.239.57', 'dst_ip': '92.255.85.173', 'dst_port': 38781, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 16, 2026 03:22:24.976522000 +08'}
  - [tls_analysis] suspicious_tls = 179.60.146.36->10.128.239.57:3389 (score=0.70) details={'entity': '179.60.146.36->10.128.239.57:3389', 'src_ip': '179.60.146.36', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Jan 16, 2026 03:39:04.063394000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.36:52175 (score=0.60) details={'entity': '10.128.239.57->179.60.146.36:52175', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'dst_port': 52175, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 16, 2026 03:39:04.124098000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->147.45.112.108:56306 (score=0.60) details={'entity': '10.128.239.57->147.45.112.108:56306', 'src_ip': '10.128.239.57', 'dst_ip': '147.45.112.108', 'dst_port': 56306, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 16, 2026 03:39:04.431784000 +08'}
  - [tls_analysis] suspicious_tls = 179.60.146.36->10.128.239.57:3389 (score=0.60) details={'entity': '179.60.146.36->10.128.239.57:3389', 'src_ip': '179.60.146.36', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 16, 2026 03:39:04.495038000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.36:52175 (score=0.60) details={'entity': '10.128.239.57->179.60.146.36:52175', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'dst_port': 52175, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 16, 2026 03:39:04.570554000 +08'}
  - [tls_analysis] suspicious_tls = 210.19.252.30->10.128.239.57:3389 (score=0.50) details={'entity': '210.19.252.30->10.128.239.57:3389', 'src_ip': '210.19.252.30', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 2, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Jan 16, 2026 03:39:04.637488000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->210.19.252.30:61381 (score=0.60) details={'entity': '10.128.239.57->210.19.252.30:61381', 'src_ip': '10.128.239.57', 'dst_ip': '210.19.252.30', 'dst_port': 61381, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 8, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 16, 2026 03:39:04.698175000 +08'}
  - [tls_analysis] suspicious_tls = 179.60.146.36->10.128.239.57:3389 (score=0.60) details={'entity': '179.60.146.36->10.128.239.57:3389', 'src_ip': '179.60.146.36', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 16, 2026 03:39:04.798747000 +08'}

### 2. Suspicious DNS Activity
- Severity: **MEDIUM**
- Confidence: **0.78**
- MITRE ATT&CK: T1071.004
- Description: High-entropy or unusually structured DNS queries suggest possible algorithmic domains, covert DNS use, or DNS-based command-and-control. Additional corroboration is required before classifying as tunneling.
- Recommendation: Perform additional containment and validation in accordance with incident response procedures.
- Affected Entities: 10.128.239.166:wdatp-prd-eus2-10.eastus2.cloudapp.azure.com, 10.128.239.21:wdatp-prd-eus2-10.eastus2.cloudapp.azure.com
- Human Review Required: Yes
- Guardrail Flags: limited_source_diversity, reportable_but_thin_evidence
- False Positive Risks:
  - High-entropy DNS can also appear in CDNs, telemetry, security products, and benign service-generated domains.
  - Repeated subdomain variation is suspicious but does not alone prove DNS tunneling.
- Missed Detection Risks:
  - Low-volume DNS covert channels may stay below threshold.
  - Benign-looking domains used by attackers may evade entropy-based heuristics.
- Technical Limitations:
  - DNS classification relies on metadata and naming patterns rather than payload semantics.
- Evidence:
  - [dns_analysis] high_entropy_dns = wdatp-prd-eus2-10.eastus2.cloudapp.azure.com (score=0.70) details={'entity': '10.128.239.166:wdatp-prd-eus2-10.eastus2.cloudapp.azure.com', 'src_ip': '10.128.239.166', 'query': 'wdatp-prd-eus2-10.eastus2.cloudapp.azure.com', 'base_domain': 'azure.com', 'qtype': '28', 'entropy': 3.996, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan 16, 2026 03:22:24.735588000 +08'}
  - [dns_analysis] high_entropy_dns = wdatp-prd-eus2-10.eastus2.cloudapp.azure.com (score=0.70) details={'entity': '10.128.239.21:wdatp-prd-eus2-10.eastus2.cloudapp.azure.com', 'src_ip': '10.128.239.21', 'query': 'wdatp-prd-eus2-10.eastus2.cloudapp.azure.com', 'base_domain': 'azure.com', 'qtype': '28', 'entropy': 3.996, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan 16, 2026 03:22:24.801613000 +08'}

## Analyst Validation Notes

The following findings should be validated by a human analyst before containment or attribution decisions:
- Suspicious DNS Activity (confidence=0.78, flags=limited_source_diversity, reportable_but_thin_evidence)

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

- 2026-04-12T14:54:41.177519Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:41.177700Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:41.177768Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:41.177770Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:41.177843Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:41.177853Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:41.177864Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:41.177891Z | materialize_findings | Generated 2 final findings