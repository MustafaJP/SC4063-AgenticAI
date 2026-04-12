# Agentic Network Forensic Report — bundle_2026-01-26_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2026-01-26_nested_overlap` and identified **2 reportable finding(s)**. The highest-confidence finding was **Suspicious DNS Activity** with confidence **1.00** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 150
- PCAP Count: 3
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
- Affected Entities: 10.128.239.82:us-v20.events.endpoint.security.microsoft.com, 10.128.239.20:us-v20.events.endpoint.security.microsoft.com, 10.128.239.21:win-global-asimov-leafs-events-data.trafficmanager.net, 13.107.222.240:win-global-asimov-leafs-events-data.trafficmanager.net, 10.128.239.21:onedscolprdweu10.westeurope.cloudapp.azure.com, 150.171.16.39:onedscolprdweu10.westeurope.cloudapp.azure.com
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
  - [dns_analysis] high_entropy_dns = us-v20.events.endpoint.security.microsoft.com (score=0.70) details={'entity': '10.128.239.82:us-v20.events.endpoint.security.microsoft.com', 'src_ip': '10.128.239.82', 'query': 'us-v20.events.endpoint.security.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.965, 'query_count': 2, 'base_domain_count': 5, 'host_count_for_query': 2, 'host_count_for_base_domain': 4, 'varying_subdomain_count': 2, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan 26, 2026 13:29:34.889508000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.endpoint.security.microsoft.com (score=0.70) details={'entity': '10.128.239.20:us-v20.events.endpoint.security.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'us-v20.events.endpoint.security.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.965, 'query_count': 2, 'base_domain_count': 5, 'host_count_for_query': 2, 'host_count_for_base_domain': 4, 'varying_subdomain_count': 2, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan 26, 2026 13:29:34.926934000 +08'}
  - [dns_analysis] high_entropy_dns = win-global-asimov-leafs-events-data.trafficmanager.net (score=1.00) details={'entity': '10.128.239.21:win-global-asimov-leafs-events-data.trafficmanager.net', 'src_ip': '10.128.239.21', 'query': 'win-global-asimov-leafs-events-data.trafficmanager.net', 'base_domain': 'trafficmanager.net', 'qtype': '1', 'entropy': 3.927, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'long_label', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Jan 26, 2026 13:29:35.276393000 +08'}
  - [dns_analysis] high_entropy_dns = win-global-asimov-leafs-events-data.trafficmanager.net (score=1.00) details={'entity': '10.128.239.21:win-global-asimov-leafs-events-data.trafficmanager.net', 'src_ip': '10.128.239.21', 'query': 'win-global-asimov-leafs-events-data.trafficmanager.net', 'base_domain': 'trafficmanager.net', 'qtype': '1', 'entropy': 3.927, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'long_label', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Jan 26, 2026 13:29:35.343091000 +08'}
  - [dns_analysis] high_entropy_dns = win-global-asimov-leafs-events-data.trafficmanager.net (score=1.00) details={'entity': '13.107.222.240:win-global-asimov-leafs-events-data.trafficmanager.net', 'src_ip': '13.107.222.240', 'query': 'win-global-asimov-leafs-events-data.trafficmanager.net', 'base_domain': 'trafficmanager.net', 'qtype': '1', 'entropy': 3.927, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'long_label', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Jan 26, 2026 13:29:35.409353000 +08'}
  - [dns_analysis] high_entropy_dns = win-global-asimov-leafs-events-data.trafficmanager.net (score=1.00) details={'entity': '13.107.222.240:win-global-asimov-leafs-events-data.trafficmanager.net', 'src_ip': '13.107.222.240', 'query': 'win-global-asimov-leafs-events-data.trafficmanager.net', 'base_domain': 'trafficmanager.net', 'qtype': '1', 'entropy': 3.927, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'long_label', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Jan 26, 2026 13:29:35.444829000 +08'}
  - [dns_analysis] high_entropy_dns = onedscolprdweu10.westeurope.cloudapp.azure.com (score=0.70) details={'entity': '10.128.239.21:onedscolprdweu10.westeurope.cloudapp.azure.com', 'src_ip': '10.128.239.21', 'query': 'onedscolprdweu10.westeurope.cloudapp.azure.com', 'base_domain': 'azure.com', 'qtype': '1', 'entropy': 3.836, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan 26, 2026 13:29:35.478087000 +08'}
  - [dns_analysis] high_entropy_dns = onedscolprdweu10.westeurope.cloudapp.azure.com (score=0.70) details={'entity': '150.171.16.39:onedscolprdweu10.westeurope.cloudapp.azure.com', 'src_ip': '150.171.16.39', 'query': 'onedscolprdweu10.westeurope.cloudapp.azure.com', 'base_domain': 'azure.com', 'qtype': '1', 'entropy': 3.836, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Jan 26, 2026 13:29:35.518038000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.73**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->88.214.25.115:34985, 10.128.239.57->91.238.181.96:25518, 10.128.239.57->79.127.132.53:47374
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->88.214.25.115:34985 (score=0.60) details={'entity': '10.128.239.57->88.214.25.115:34985', 'src_ip': '10.128.239.57', 'dst_ip': '88.214.25.115', 'dst_port': 34985, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 26, 2026 13:29:34.856927000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.96:25518 (score=0.60) details={'entity': '10.128.239.57->91.238.181.96:25518', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.96', 'dst_port': 25518, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 26, 2026 13:29:34.990102000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->79.127.132.53:47374 (score=0.60) details={'entity': '10.128.239.57->79.127.132.53:47374', 'src_ip': '10.128.239.57', 'dst_ip': '79.127.132.53', 'dst_port': 47374, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Jan 26, 2026 13:29:35.086970000 +08'}

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

- 2026-04-12T14:54:41.233661Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:41.233961Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:41.234130Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:41.234134Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:41.234173Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:41.234189Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:41.234198Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:41.234226Z | materialize_findings | Generated 2 final findings