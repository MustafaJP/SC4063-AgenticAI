# Agentic Network Forensic Report — bundle_2026-01-04_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-04_nested_overlap` and identified **2 reportable finding(s)**. The highest-confidence finding was **Suspicious DNS Activity** with confidence **0.88** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 152
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
- Confidence: **0.88**
- MITRE ATT&CK: T1071.004
- Description: High-entropy or unusually structured DNS queries suggest possible algorithmic domains, covert DNS use, or DNS-based command-and-control. Additional corroboration is required before classifying as tunneling.
- Recommendation: Perform additional containment and validation in accordance with incident response procedures.
- Affected Entities: 10.128.239.166:wdatp-prd-eus2-10.eastus2.cloudapp.azure.com, 10.128.239.20:wdatp-prd-eus2-10.eastus2.cloudapp.azure.com, 10.128.239.54:us-v20.events.endpoint.security.microsoft.com, 10.128.239.20:us-v20.events.endpoint.security.microsoft.com
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
  - [dns_analysis] high_entropy_dns = wdatp-prd-eus2-10.eastus2.cloudapp.azure.com (score=0.70) details={'entity': '10.128.239.166:wdatp-prd-eus2-10.eastus2.cloudapp.azure.com', 'src_ip': '10.128.239.166', 'query': 'wdatp-prd-eus2-10.eastus2.cloudapp.azure.com', 'base_domain': 'azure.com', 'qtype': '1', 'entropy': 3.996, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan  4, 2026 06:29:38.861896000 +08'}
  - [dns_analysis] high_entropy_dns = wdatp-prd-eus2-10.eastus2.cloudapp.azure.com (score=0.70) details={'entity': '10.128.239.20:wdatp-prd-eus2-10.eastus2.cloudapp.azure.com', 'src_ip': '10.128.239.20', 'query': 'wdatp-prd-eus2-10.eastus2.cloudapp.azure.com', 'base_domain': 'azure.com', 'qtype': '1', 'entropy': 3.996, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan  4, 2026 06:29:38.924651000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.endpoint.security.microsoft.com (score=0.70) details={'entity': '10.128.239.54:us-v20.events.endpoint.security.microsoft.com', 'src_ip': '10.128.239.54', 'query': 'us-v20.events.endpoint.security.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.965, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan  4, 2026 06:29:39.113702000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.endpoint.security.microsoft.com (score=0.70) details={'entity': '10.128.239.20:us-v20.events.endpoint.security.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'us-v20.events.endpoint.security.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.965, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan  4, 2026 06:29:39.181681000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.83**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 179.60.146.37->10.128.239.57:3389, 10.128.239.57->179.60.146.37:51394, 10.128.239.57->45.227.254.3:12976, 141.98.11.109->10.128.239.57:3389, 10.128.239.57->141.98.11.109:48366, 10.128.239.57->98.159.33.51:3082
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
  - [tls_analysis] suspicious_tls = 179.60.146.37->10.128.239.57:3389 (score=0.50) details={'entity': '179.60.146.37->10.128.239.57:3389', 'src_ip': '179.60.146.37', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 2, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 06:29:38.994363000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.37:51394 (score=0.60) details={'entity': '10.128.239.57->179.60.146.37:51394', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.37', 'dst_port': 51394, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 06:29:39.054711000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.227.254.3:12976 (score=0.60) details={'entity': '10.128.239.57->45.227.254.3:12976', 'src_ip': '10.128.239.57', 'dst_ip': '45.227.254.3', 'dst_port': 12976, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 06:29:39.298886000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.37:51394 (score=0.60) details={'entity': '10.128.239.57->179.60.146.37:51394', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.37', 'dst_port': 51394, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 06:29:39.609529000 +08'}
  - [tls_analysis] suspicious_tls = 141.98.11.109->10.128.239.57:3389 (score=0.60) details={'entity': '141.98.11.109->10.128.239.57:3389', 'src_ip': '141.98.11.109', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 16:36:44.335395000 +08'}
  - [tls_analysis] suspicious_tls = 141.98.11.109->10.128.239.57:3389 (score=0.60) details={'entity': '141.98.11.109->10.128.239.57:3389', 'src_ip': '141.98.11.109', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 16:36:44.725652000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.109:48366 (score=0.60) details={'entity': '10.128.239.57->141.98.11.109:48366', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.109', 'dst_port': 48366, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 16:36:44.784565000 +08'}
  - [tls_analysis] suspicious_tls = 141.98.11.109->10.128.239.57:3389 (score=0.60) details={'entity': '141.98.11.109->10.128.239.57:3389', 'src_ip': '141.98.11.109', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '1', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 16:36:45.071282000 +08'}
  - [tls_analysis] suspicious_tls = 141.98.11.109->10.128.239.57:3389 (score=0.70) details={'entity': '141.98.11.109->10.128.239.57:3389', 'src_ip': '141.98.11.109', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 16:36:45.240366000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.109:48366 (score=0.60) details={'entity': '10.128.239.57->141.98.11.109:48366', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.109', 'dst_port': 48366, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 16:36:45.299688000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->98.159.33.51:3082 (score=0.60) details={'entity': '10.128.239.57->98.159.33.51:3082', 'src_ip': '10.128.239.57', 'dst_ip': '98.159.33.51', 'dst_port': 3082, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 6, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan  4, 2026 19:09:50.082233000 +08'}

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

- 2026-04-12T14:54:41.110336Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:41.110663Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:41.110800Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:41.110803Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:41.110867Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:41.110884Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:41.110895Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:41.110924Z | materialize_findings | Generated 2 final findings