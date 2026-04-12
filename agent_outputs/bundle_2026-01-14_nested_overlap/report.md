# Agentic Network Forensic Report — bundle_2026-01-14_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-14_nested_overlap` and identified **2 reportable finding(s)**. The highest-confidence finding was **Suspicious TLS Session** with confidence **0.81** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 147
- PCAP Count: 3
- Hypothesis Count: 2
- Finding Count: 2
- Analysis Runtime (seconds): 0.001
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
- Confidence: **0.81**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 85.237.194.86->10.128.239.57:3389, 10.128.239.57->85.237.194.86:2626, 10.128.239.57->194.165.17.11:6784, 194.165.17.11->10.128.239.57:3389, 10.128.239.57->194.165.17.11:18265, 10.128.239.57->88.214.25.115:19941, 10.128.239.57->45.141.87.201:31139, 10.128.239.57->45.141.87.46:34889, 10.128.239.57->45.135.232.20:5958, 179.60.146.32->10.128.239.57:3389, 91.199.163.12->10.128.239.57:3389, 10.128.239.57->179.60.146.32:53769, 10.128.239.57->91.199.163.12:30900, 45.141.87.151->10.128.239.57:3389
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
  - [tls_analysis] suspicious_tls = 85.237.194.86->10.128.239.57:3389 (score=0.50) details={'entity': '85.237.194.86->10.128.239.57:3389', 'src_ip': '85.237.194.86', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 2, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 01:21:43.457764000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->85.237.194.86:2626 (score=0.60) details={'entity': '10.128.239.57->85.237.194.86:2626', 'src_ip': '10.128.239.57', 'dst_ip': '85.237.194.86', 'dst_port': 2626, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 10, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 01:21:43.519919000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->85.237.194.86:2626 (score=0.60) details={'entity': '10.128.239.57->85.237.194.86:2626', 'src_ip': '10.128.239.57', 'dst_ip': '85.237.194.86', 'dst_port': 2626, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 10, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 01:21:43.667441000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->194.165.17.11:6784 (score=0.60) details={'entity': '10.128.239.57->194.165.17.11:6784', 'src_ip': '10.128.239.57', 'dst_ip': '194.165.17.11', 'dst_port': 6784, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 10, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:11:25.679175000 +08'}
  - [tls_analysis] suspicious_tls = 194.165.17.11->10.128.239.57:3389 (score=0.60) details={'entity': '194.165.17.11->10.128.239.57:3389', 'src_ip': '194.165.17.11', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:11:25.741237000 +08'}
  - [tls_analysis] suspicious_tls = 194.165.17.11->10.128.239.57:3389 (score=0.60) details={'entity': '194.165.17.11->10.128.239.57:3389', 'src_ip': '194.165.17.11', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:11:25.801680000 +08'}
  - [tls_analysis] suspicious_tls = 194.165.17.11->10.128.239.57:3389 (score=0.60) details={'entity': '194.165.17.11->10.128.239.57:3389', 'src_ip': '194.165.17.11', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:11:26.324687000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->194.165.17.11:18265 (score=0.60) details={'entity': '10.128.239.57->194.165.17.11:18265', 'src_ip': '10.128.239.57', 'dst_ip': '194.165.17.11', 'dst_port': 18265, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 10, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:11:26.384563000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->88.214.25.115:19941 (score=0.60) details={'entity': '10.128.239.57->88.214.25.115:19941', 'src_ip': '10.128.239.57', 'dst_ip': '88.214.25.115', 'dst_port': 19941, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 10, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:11:26.502307000 +08'}
  - [tls_analysis] suspicious_tls = 194.165.17.11->10.128.239.57:3389 (score=0.60) details={'entity': '194.165.17.11->10.128.239.57:3389', 'src_ip': '194.165.17.11', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '1', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:11:26.568959000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.141.87.201:31139 (score=0.60) details={'entity': '10.128.239.57->45.141.87.201:31139', 'src_ip': '10.128.239.57', 'dst_ip': '45.141.87.201', 'dst_port': 31139, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 10, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:44:49.666955000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.141.87.46:34889 (score=0.60) details={'entity': '10.128.239.57->45.141.87.46:34889', 'src_ip': '10.128.239.57', 'dst_ip': '45.141.87.46', 'dst_port': 34889, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 10, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:44:49.850173000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.135.232.20:5958 (score=0.60) details={'entity': '10.128.239.57->45.135.232.20:5958', 'src_ip': '10.128.239.57', 'dst_ip': '45.135.232.20', 'dst_port': 5958, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 10, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:44:50.214531000 +08'}
  - [tls_analysis] suspicious_tls = 179.60.146.32->10.128.239.57:3389 (score=0.50) details={'entity': '179.60.146.32->10.128.239.57:3389', 'src_ip': '179.60.146.32', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 1, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:44:50.253194000 +08'}
  - [tls_analysis] suspicious_tls = 91.199.163.12->10.128.239.57:3389 (score=0.50) details={'entity': '91.199.163.12->10.128.239.57:3389', 'src_ip': '91.199.163.12', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 1, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:44:50.290165000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.32:53769 (score=0.60) details={'entity': '10.128.239.57->179.60.146.32:53769', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.32', 'dst_port': 53769, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 10, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:44:50.323087000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.199.163.12:30900 (score=0.60) details={'entity': '10.128.239.57->91.199.163.12:30900', 'src_ip': '10.128.239.57', 'dst_ip': '91.199.163.12', 'dst_port': 30900, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 10, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:44:50.356233000 +08'}
  - [tls_analysis] suspicious_tls = 45.141.87.151->10.128.239.57:3389 (score=0.50) details={'entity': '45.141.87.151->10.128.239.57:3389', 'src_ip': '45.141.87.151', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 2, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Jan 14, 2026 05:44:50.607050000 +08'}

### 2. Suspicious DNS Activity
- Severity: **MEDIUM**
- Confidence: **0.78**
- MITRE ATT&CK: T1071.004
- Description: High-entropy or unusually structured DNS queries suggest possible algorithmic domains, covert DNS use, or DNS-based command-and-control. Additional corroboration is required before classifying as tunneling.
- Recommendation: Perform additional containment and validation in accordance with incident response procedures.
- Affected Entities: 10.128.239.44:us-v20.events.endpoint.security.microsoft.com, 10.128.239.20:us-v20.events.endpoint.security.microsoft.com
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
  - [dns_analysis] high_entropy_dns = us-v20.events.endpoint.security.microsoft.com (score=0.70) details={'entity': '10.128.239.44:us-v20.events.endpoint.security.microsoft.com', 'src_ip': '10.128.239.44', 'query': 'us-v20.events.endpoint.security.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.965, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan 14, 2026 01:21:43.728728000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.endpoint.security.microsoft.com (score=0.70) details={'entity': '10.128.239.20:us-v20.events.endpoint.security.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'us-v20.events.endpoint.security.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.965, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan 14, 2026 01:21:43.802369000 +08'}

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

- 2026-04-12T14:54:41.163776Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:41.164111Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:41.164182Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:41.164185Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:41.164277Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:41.164291Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:41.164302Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:41.164326Z | materialize_findings | Generated 2 final findings