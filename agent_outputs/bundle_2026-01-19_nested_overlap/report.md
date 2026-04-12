# Agentic Network Forensic Report — bundle_2026-01-19_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-19_nested_overlap` and identified **2 reportable finding(s)**. The highest-confidence finding was **Suspicious DNS Activity** with confidence **1.00** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 182
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
- Affected Entities: 10.128.239.171:us-v20.events.data.microsoft.com, 10.128.239.20:us-v20.events.data.microsoft.com, 10.128.239.115:settings-win.data.microsoft.com, 10.128.239.21:settings-prod-eus2-1.eastus2.cloudapp.azure.com, 10.128.239.20:settings-win.data.microsoft.com, 13.107.236.6:settings-prod-eus2-1.eastus2.cloudapp.azure.com, 10.128.239.21:settings-win.data.microsoft.com, 10.128.239.50:us-v20.events.endpoint.security.microsoft.com, 10.128.239.20:us-v20.events.endpoint.security.microsoft.com
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
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=1.00) details={'entity': '10.128.239.171:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.171', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.941, 'query_count': 8, 'base_domain_count': 17, 'host_count_for_query': 2, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 01:09:44.130626000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=1.00) details={'entity': '10.128.239.171:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.171', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '28', 'entropy': 3.941, 'query_count': 8, 'base_domain_count': 17, 'host_count_for_query': 2, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 01:09:44.163429000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=1.00) details={'entity': '10.128.239.20:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.941, 'query_count': 8, 'base_domain_count': 17, 'host_count_for_query': 2, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 01:09:44.199933000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=1.00) details={'entity': '10.128.239.20:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '28', 'entropy': 3.941, 'query_count': 8, 'base_domain_count': 17, 'host_count_for_query': 2, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 01:09:44.240453000 +08'}
  - [dns_analysis] high_entropy_dns = settings-win.data.microsoft.com (score=0.60) details={'entity': '10.128.239.115:settings-win.data.microsoft.com', 'src_ip': '10.128.239.115', 'query': 'settings-win.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.726, 'query_count': 5, 'base_domain_count': 17, 'host_count_for_query': 3, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['repeated_domain', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 01:09:44.273711000 +08'}
  - [dns_analysis] high_entropy_dns = settings-win.data.microsoft.com (score=0.60) details={'entity': '10.128.239.115:settings-win.data.microsoft.com', 'src_ip': '10.128.239.115', 'query': 'settings-win.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.726, 'query_count': 5, 'base_domain_count': 17, 'host_count_for_query': 3, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['repeated_domain', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 01:09:44.305886000 +08'}
  - [dns_analysis] high_entropy_dns = settings-prod-eus2-1.eastus2.cloudapp.azure.com (score=0.70) details={'entity': '10.128.239.21:settings-prod-eus2-1.eastus2.cloudapp.azure.com', 'src_ip': '10.128.239.21', 'query': 'settings-prod-eus2-1.eastus2.cloudapp.azure.com', 'base_domain': 'azure.com', 'qtype': '1', 'entropy': 4.045, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan 19, 2026 01:09:44.339122000 +08'}
  - [dns_analysis] high_entropy_dns = settings-win.data.microsoft.com (score=0.60) details={'entity': '10.128.239.20:settings-win.data.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'settings-win.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.726, 'query_count': 5, 'base_domain_count': 17, 'host_count_for_query': 3, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['repeated_domain', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 01:09:44.376492000 +08'}
  - [dns_analysis] high_entropy_dns = settings-prod-eus2-1.eastus2.cloudapp.azure.com (score=0.70) details={'entity': '13.107.236.6:settings-prod-eus2-1.eastus2.cloudapp.azure.com', 'src_ip': '13.107.236.6', 'query': 'settings-prod-eus2-1.eastus2.cloudapp.azure.com', 'base_domain': 'azure.com', 'qtype': '1', 'entropy': 4.045, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan 19, 2026 01:09:44.410977000 +08'}
  - [dns_analysis] high_entropy_dns = settings-win.data.microsoft.com (score=0.60) details={'entity': '10.128.239.21:settings-win.data.microsoft.com', 'src_ip': '10.128.239.21', 'query': 'settings-win.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.726, 'query_count': 5, 'base_domain_count': 17, 'host_count_for_query': 3, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['repeated_domain', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 01:09:44.449543000 +08'}
  - [dns_analysis] high_entropy_dns = settings-win.data.microsoft.com (score=0.60) details={'entity': '10.128.239.115:settings-win.data.microsoft.com', 'src_ip': '10.128.239.115', 'query': 'settings-win.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.726, 'query_count': 5, 'base_domain_count': 17, 'host_count_for_query': 3, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['repeated_domain', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 01:09:44.488818000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=1.00) details={'entity': '10.128.239.171:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.171', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.941, 'query_count': 8, 'base_domain_count': 17, 'host_count_for_query': 2, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 23:50:55.172724000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=1.00) details={'entity': '10.128.239.171:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.171', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '28', 'entropy': 3.941, 'query_count': 8, 'base_domain_count': 17, 'host_count_for_query': 2, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 23:50:55.230858000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=1.00) details={'entity': '10.128.239.20:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.941, 'query_count': 8, 'base_domain_count': 17, 'host_count_for_query': 2, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 23:50:55.352853000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=1.00) details={'entity': '10.128.239.20:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '28', 'entropy': 3.941, 'query_count': 8, 'base_domain_count': 17, 'host_count_for_query': 2, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 23:50:55.425945000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.endpoint.security.microsoft.com (score=0.90) details={'entity': '10.128.239.50:us-v20.events.endpoint.security.microsoft.com', 'src_ip': '10.128.239.50', 'query': 'us-v20.events.endpoint.security.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.965, 'query_count': 2, 'base_domain_count': 17, 'host_count_for_query': 2, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['high_entropy', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 23:50:55.774793000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.endpoint.security.microsoft.com (score=0.90) details={'entity': '10.128.239.20:us-v20.events.endpoint.security.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'us-v20.events.endpoint.security.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.965, 'query_count': 2, 'base_domain_count': 17, 'host_count_for_query': 2, 'host_count_for_base_domain': 6, 'varying_subdomain_count': 4, 'reasons': ['high_entropy', 'multi_host_domain', 'varying_subdomains_same_base'], 'event_timestamp': 'Jan 19, 2026 23:50:55.847855000 +08'}

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

- 2026-04-12T14:54:41.194112Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:41.194501Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:41.194818Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:41.194821Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:41.194871Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:41.194891Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:41.194905Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:41.194934Z | materialize_findings | Generated 2 final findings