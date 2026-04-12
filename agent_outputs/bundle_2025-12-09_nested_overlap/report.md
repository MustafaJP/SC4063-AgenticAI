# Agentic Network Forensic Report — bundle_2025-12-09_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2025-12-09_nested_overlap` and identified **2 reportable finding(s)**. The highest-confidence finding was **Suspicious DNS Activity** with confidence **1.00** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 198
- PCAP Count: 5
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
- Affected Entities: 10.128.239.20:atm-settingsfe-prod-geo2.trafficmanager.net, 10.128.239.21:atm-settingsfe-prod-geo2.trafficmanager.net, 13.107.222.240:atm-settingsfe-prod-geo2.trafficmanager.net, 10.128.239.21:settings-prod-wus2-1.westus2.cloudapp.azure.com, 150.171.21.2:settings-prod-wus2-1.westus2.cloudapp.azure.com
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
  - [dns_analysis] high_entropy_dns = atm-settingsfe-prod-geo2.trafficmanager.net (score=0.90) details={'entity': '10.128.239.20:atm-settingsfe-prod-geo2.trafficmanager.net', 'src_ip': '10.128.239.20', 'query': 'atm-settingsfe-prod-geo2.trafficmanager.net', 'base_domain': 'trafficmanager.net', 'qtype': '1', 'entropy': 3.821, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 3, 'host_count_for_base_domain': 3, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec  9, 2025 20:47:42.848746000 +08'}
  - [dns_analysis] high_entropy_dns = atm-settingsfe-prod-geo2.trafficmanager.net (score=0.90) details={'entity': '10.128.239.21:atm-settingsfe-prod-geo2.trafficmanager.net', 'src_ip': '10.128.239.21', 'query': 'atm-settingsfe-prod-geo2.trafficmanager.net', 'base_domain': 'trafficmanager.net', 'qtype': '1', 'entropy': 3.821, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 3, 'host_count_for_base_domain': 3, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec  9, 2025 20:47:42.964198000 +08'}
  - [dns_analysis] high_entropy_dns = atm-settingsfe-prod-geo2.trafficmanager.net (score=0.90) details={'entity': '13.107.222.240:atm-settingsfe-prod-geo2.trafficmanager.net', 'src_ip': '13.107.222.240', 'query': 'atm-settingsfe-prod-geo2.trafficmanager.net', 'base_domain': 'trafficmanager.net', 'qtype': '1', 'entropy': 3.821, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 3, 'host_count_for_base_domain': 3, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec  9, 2025 20:47:43.028093000 +08'}
  - [dns_analysis] high_entropy_dns = settings-prod-wus2-1.westus2.cloudapp.azure.com (score=0.70) details={'entity': '10.128.239.21:settings-prod-wus2-1.westus2.cloudapp.azure.com', 'src_ip': '10.128.239.21', 'query': 'settings-prod-wus2-1.westus2.cloudapp.azure.com', 'base_domain': 'azure.com', 'qtype': '1', 'entropy': 4.138, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Dec  9, 2025 20:47:43.090054000 +08'}
  - [dns_analysis] high_entropy_dns = atm-settingsfe-prod-geo2.trafficmanager.net (score=0.90) details={'entity': '10.128.239.21:atm-settingsfe-prod-geo2.trafficmanager.net', 'src_ip': '10.128.239.21', 'query': 'atm-settingsfe-prod-geo2.trafficmanager.net', 'base_domain': 'trafficmanager.net', 'qtype': '1', 'entropy': 3.821, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 3, 'host_count_for_base_domain': 3, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec  9, 2025 20:47:43.157738000 +08'}
  - [dns_analysis] high_entropy_dns = settings-prod-wus2-1.westus2.cloudapp.azure.com (score=0.70) details={'entity': '150.171.21.2:settings-prod-wus2-1.westus2.cloudapp.azure.com', 'src_ip': '150.171.21.2', 'query': 'settings-prod-wus2-1.westus2.cloudapp.azure.com', 'base_domain': 'azure.com', 'qtype': '1', 'entropy': 4.138, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Dec  9, 2025 20:47:43.288294000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.81**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->194.165.16.167:26425, 45.227.254.152->10.128.239.57:3389, 10.128.239.57->45.227.254.152:8136, 10.128.239.57->91.238.181.93:27205, 179.60.146.36->10.128.239.57:3389, 10.128.239.57->179.60.146.36:50607, 91.238.181.39->10.128.239.57:3389, 147.45.112.181->10.128.239.57:3389, 10.128.239.57->147.45.112.181:2422, 10.128.239.57->88.214.25.121:4781, 88.214.25.125->10.128.239.57:3389, 10.128.239.57->88.214.25.125:7761, 10.128.239.57->179.60.146.36:64260
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->194.165.16.167:26425 (score=0.60) details={'entity': '10.128.239.57->194.165.16.167:26425', 'src_ip': '10.128.239.57', 'dst_ip': '194.165.16.167', 'dst_port': 26425, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 03:31:37.307635000 +08'}
  - [tls_analysis] suspicious_tls = 45.227.254.152->10.128.239.57:3389 (score=0.50) details={'entity': '45.227.254.152->10.128.239.57:3389', 'src_ip': '45.227.254.152', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 1, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 03:31:37.848680000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.227.254.152:8136 (score=0.60) details={'entity': '10.128.239.57->45.227.254.152:8136', 'src_ip': '10.128.239.57', 'dst_ip': '45.227.254.152', 'dst_port': 8136, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 03:31:37.905295000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.93:27205 (score=0.60) details={'entity': '10.128.239.57->91.238.181.93:27205', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.93', 'dst_port': 27205, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 03:42:46.335899000 +08'}
  - [tls_analysis] suspicious_tls = 179.60.146.36->10.128.239.57:3389 (score=0.60) details={'entity': '179.60.146.36->10.128.239.57:3389', 'src_ip': '179.60.146.36', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 04:09:33.296005000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.36:50607 (score=0.60) details={'entity': '10.128.239.57->179.60.146.36:50607', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'dst_port': 50607, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 04:09:33.376012000 +08'}
  - [tls_analysis] suspicious_tls = 91.238.181.39->10.128.239.57:3389 (score=0.60) details={'entity': '91.238.181.39->10.128.239.57:3389', 'src_ip': '91.238.181.39', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 04:09:33.439010000 +08'}
  - [tls_analysis] suspicious_tls = 179.60.146.36->10.128.239.57:3389 (score=0.60) details={'entity': '179.60.146.36->10.128.239.57:3389', 'src_ip': '179.60.146.36', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 04:09:33.713308000 +08'}
  - [tls_analysis] suspicious_tls = 91.238.181.39->10.128.239.57:3389 (score=0.60) details={'entity': '91.238.181.39->10.128.239.57:3389', 'src_ip': '91.238.181.39', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 04:09:33.942887000 +08'}
  - [tls_analysis] suspicious_tls = 147.45.112.181->10.128.239.57:3389 (score=0.50) details={'entity': '147.45.112.181->10.128.239.57:3389', 'src_ip': '147.45.112.181', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 2, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 08:35:16.491688000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->147.45.112.181:2422 (score=0.60) details={'entity': '10.128.239.57->147.45.112.181:2422', 'src_ip': '10.128.239.57', 'dst_ip': '147.45.112.181', 'dst_port': 2422, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 08:35:16.550783000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->88.214.25.121:4781 (score=0.60) details={'entity': '10.128.239.57->88.214.25.121:4781', 'src_ip': '10.128.239.57', 'dst_ip': '88.214.25.121', 'dst_port': 4781, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 08:35:16.852634000 +08'}
  - [tls_analysis] suspicious_tls = 88.214.25.125->10.128.239.57:3389 (score=0.50) details={'entity': '88.214.25.125->10.128.239.57:3389', 'src_ip': '88.214.25.125', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 1, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 08:35:16.920170000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->88.214.25.125:7761 (score=0.60) details={'entity': '10.128.239.57->88.214.25.125:7761', 'src_ip': '10.128.239.57', 'dst_ip': '88.214.25.125', 'dst_port': 7761, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 08:35:16.980396000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->147.45.112.181:2422 (score=0.60) details={'entity': '10.128.239.57->147.45.112.181:2422', 'src_ip': '10.128.239.57', 'dst_ip': '147.45.112.181', 'dst_port': 2422, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 08:35:17.120799000 +08'}
  - [tls_analysis] suspicious_tls = 179.60.146.36->10.128.239.57:3389 (score=0.60) details={'entity': '179.60.146.36->10.128.239.57:3389', 'src_ip': '179.60.146.36', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 20:47:42.497551000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.36:64260 (score=0.60) details={'entity': '10.128.239.57->179.60.146.36:64260', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'dst_port': 64260, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 9, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 20:47:42.575579000 +08'}
  - [tls_analysis] suspicious_tls = 179.60.146.36->10.128.239.57:3389 (score=0.60) details={'entity': '179.60.146.36->10.128.239.57:3389', 'src_ip': '179.60.146.36', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 20:47:42.730727000 +08'}
  - [tls_analysis] suspicious_tls = 91.238.181.39->10.128.239.57:3389 (score=0.60) details={'entity': '91.238.181.39->10.128.239.57:3389', 'src_ip': '91.238.181.39', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  9, 2025 20:47:43.460138000 +08'}

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

- 2026-04-12T14:54:40.972909Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:40.973366Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:40.973577Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:40.973580Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:40.973755Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:40.973772Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:40.973785Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:40.973811Z | materialize_findings | Generated 2 final findings