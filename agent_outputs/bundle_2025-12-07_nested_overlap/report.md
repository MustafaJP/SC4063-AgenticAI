# Agentic Network Forensic Report — bundle_2025-12-07_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2025-12-07_nested_overlap` and identified **2 reportable finding(s)**. The highest-confidence finding was **Suspicious DNS Activity** with confidence **1.00** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 156
- PCAP Count: 4
- Hypothesis Count: 2
- Finding Count: 2
- Analysis Runtime (seconds): 0.001
- Estimated Analysis Cost: 0.0
- Human Review Required Count: 0
- Guardrailed Hypothesis Count: 2

## Safety Controls and Guardrails

- **minimum_evidence_requirement**: Hypotheses with fewer than 2 evidence items are downgraded below formal reporting threshold.
- **confidence_threshold_for_reporting**: Only hypotheses with confidence >= 0.6 are materialized as findings.
- **human_review_for_high_impact_or_thin_claims**: Potentially high-impact findings and thinly corroborated claims are flagged for analyst validation before operational use.
- **source_diversity_tracking**: Hypotheses record whether evidence came from limited or multiple analytic sources.

## Findings

### 1. Suspicious DNS Activity
- Severity: **MEDIUM**
- Confidence: **1.00**
- MITRE ATT&CK: T1071.004
- Description: High-entropy or unusually structured DNS queries suggest possible algorithmic domains, covert DNS use, or DNS-based command-and-control. Additional corroboration is required before classifying as tunneling.
- Recommendation: Perform additional containment and validation in accordance with incident response procedures.
- Affected Entities: 10.128.239.21:edge.ds-c7114-microsoft.global.dns.qwilted-cds.cqloud.com, 15.197.148.211:edge.ds-c7114-microsoft.global.dns.qwilted-cds.cqloud.com, 10.128.239.171:us-v20.events.data.microsoft.com, 10.128.239.20:us-v20.events.data.microsoft.com
- Human Review Required: No
- Guardrail Flags: limited_source_diversity
- False Positive Risks:
  - High-entropy DNS can also appear in CDNs, telemetry, security products, and benign service-generated domains.
  - Repeated subdomain variation is suspicious but does not alone prove DNS tunneling.
- Missed Detection Risks:
  - Low-volume DNS covert channels may stay below threshold.
  - Benign-looking domains used by attackers may evade entropy-based heuristics.
- Technical Limitations:
  - DNS classification relies on metadata and naming patterns rather than payload semantics.
- Evidence:
  - [dns_analysis] high_entropy_dns = edge.ds-c7114-microsoft.global.dns.qwilted-cds.cqloud.com (score=0.70) details={'entity': '10.128.239.21:edge.ds-c7114-microsoft.global.dns.qwilted-cds.cqloud.com', 'src_ip': '10.128.239.21', 'query': 'edge.ds-c7114-microsoft.global.dns.qwilted-cds.cqloud.com', 'base_domain': 'cqloud.com', 'qtype': '1', 'entropy': 4.178, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Dec  7, 2025 15:59:35.631893000 +08'}
  - [dns_analysis] high_entropy_dns = edge.ds-c7114-microsoft.global.dns.qwilted-cds.cqloud.com (score=0.70) details={'entity': '15.197.148.211:edge.ds-c7114-microsoft.global.dns.qwilted-cds.cqloud.com', 'src_ip': '15.197.148.211', 'query': 'edge.ds-c7114-microsoft.global.dns.qwilted-cds.cqloud.com', 'base_domain': 'cqloud.com', 'qtype': '1', 'entropy': 4.178, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Dec  7, 2025 15:59:35.747982000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=0.90) details={'entity': '10.128.239.171:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.171', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.941, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec  7, 2025 16:35:46.518729000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=0.90) details={'entity': '10.128.239.171:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.171', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '28', 'entropy': 3.941, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec  7, 2025 16:35:46.577107000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=0.90) details={'entity': '10.128.239.20:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.941, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec  7, 2025 16:35:46.643070000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=0.90) details={'entity': '10.128.239.20:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '28', 'entropy': 3.941, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec  7, 2025 16:35:46.715026000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.83**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->150.242.202.185:50286, 10.128.239.57->179.60.146.33:55220, 10.128.239.57->91.238.181.7:44928, 10.128.239.57->179.60.146.33:63085, 10.128.239.57->88.214.25.115:7102, 10.128.239.57->91.238.181.93:45627, 10.128.239.57->194.165.16.167:14433, 10.128.239.57->45.227.254.151:56649
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->150.242.202.185:50286 (score=0.60) details={'entity': '10.128.239.57->150.242.202.185:50286', 'src_ip': '10.128.239.57', 'dst_ip': '150.242.202.185', 'dst_port': 50286, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  7, 2025 11:05:37.301265000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->150.242.202.185:50286 (score=0.60) details={'entity': '10.128.239.57->150.242.202.185:50286', 'src_ip': '10.128.239.57', 'dst_ip': '150.242.202.185', 'dst_port': 50286, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  7, 2025 11:05:37.779727000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.33:55220 (score=0.60) details={'entity': '10.128.239.57->179.60.146.33:55220', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.33', 'dst_port': 55220, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  7, 2025 11:05:38.038554000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.7:44928 (score=0.60) details={'entity': '10.128.239.57->91.238.181.7:44928', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.7', 'dst_port': 44928, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  7, 2025 11:05:38.098409000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.33:63085 (score=0.60) details={'entity': '10.128.239.57->179.60.146.33:63085', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.33', 'dst_port': 63085, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  7, 2025 11:05:38.156796000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->88.214.25.115:7102 (score=0.60) details={'entity': '10.128.239.57->88.214.25.115:7102', 'src_ip': '10.128.239.57', 'dst_ip': '88.214.25.115', 'dst_port': 7102, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  7, 2025 15:59:35.514468000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.93:45627 (score=0.60) details={'entity': '10.128.239.57->91.238.181.93:45627', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.93', 'dst_port': 45627, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  7, 2025 16:35:46.401007000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->194.165.16.167:14433 (score=0.60) details={'entity': '10.128.239.57->194.165.16.167:14433', 'src_ip': '10.128.239.57', 'dst_ip': '194.165.16.167', 'dst_port': 14433, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  7, 2025 16:35:46.459012000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.227.254.151:56649 (score=0.60) details={'entity': '10.128.239.57->45.227.254.151:56649', 'src_ip': '10.128.239.57', 'dst_ip': '45.227.254.151', 'dst_port': 56649, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  7, 2025 16:35:47.343549000 +08'}

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

- 2026-04-12T14:54:40.957078Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:40.957381Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:40.957519Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:40.957521Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:40.957581Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:40.957596Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:40.957606Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:40.957631Z | materialize_findings | Generated 2 final findings