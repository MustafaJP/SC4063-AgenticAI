# Agentic Network Forensic Report — bundle_2025-12-03_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2025-12-03_nested_overlap` and identified **2 reportable finding(s)**. The highest-confidence finding was **Suspicious DNS Activity** with confidence **0.98** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 122
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
- Confidence: **0.98**
- MITRE ATT&CK: T1071.004
- Description: High-entropy or unusually structured DNS queries suggest possible algorithmic domains, covert DNS use, or DNS-based command-and-control. Additional corroboration is required before classifying as tunneling.
- Recommendation: Perform additional containment and validation in accordance with incident response procedures.
- Affected Entities: 10.128.239.21:win-global-asimov-leafs-events-data.trafficmanager.net, 13.107.222.240:win-global-asimov-leafs-events-data.trafficmanager.net, 10.128.239.21:onedscolprdcus10.centralus.cloudapp.azure.com, 204.14.183.201:onedscolprdcus10.centralus.cloudapp.azure.com
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
  - [dns_analysis] high_entropy_dns = win-global-asimov-leafs-events-data.trafficmanager.net (score=0.90) details={'entity': '10.128.239.21:win-global-asimov-leafs-events-data.trafficmanager.net', 'src_ip': '10.128.239.21', 'query': 'win-global-asimov-leafs-events-data.trafficmanager.net', 'base_domain': 'trafficmanager.net', 'qtype': '1', 'entropy': 3.927, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'long_label', 'multi_host_domain'], 'event_timestamp': 'Dec  3, 2025 06:28:07.160439000 +08'}
  - [dns_analysis] high_entropy_dns = win-global-asimov-leafs-events-data.trafficmanager.net (score=0.90) details={'entity': '13.107.222.240:win-global-asimov-leafs-events-data.trafficmanager.net', 'src_ip': '13.107.222.240', 'query': 'win-global-asimov-leafs-events-data.trafficmanager.net', 'base_domain': 'trafficmanager.net', 'qtype': '1', 'entropy': 3.927, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'long_label', 'multi_host_domain'], 'event_timestamp': 'Dec  3, 2025 06:28:07.291875000 +08'}
  - [dns_analysis] high_entropy_dns = onedscolprdcus10.centralus.cloudapp.azure.com (score=0.70) details={'entity': '10.128.239.21:onedscolprdcus10.centralus.cloudapp.azure.com', 'src_ip': '10.128.239.21', 'query': 'onedscolprdcus10.centralus.cloudapp.azure.com', 'base_domain': 'azure.com', 'qtype': '1', 'entropy': 3.824, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Dec  3, 2025 06:28:07.356088000 +08'}
  - [dns_analysis] high_entropy_dns = onedscolprdcus10.centralus.cloudapp.azure.com (score=0.70) details={'entity': '204.14.183.201:onedscolprdcus10.centralus.cloudapp.azure.com', 'src_ip': '204.14.183.201', 'query': 'onedscolprdcus10.centralus.cloudapp.azure.com', 'base_domain': 'azure.com', 'qtype': '1', 'entropy': 3.824, 'query_count': 2, 'base_domain_count': 2, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'multi_host_domain'], 'event_timestamp': 'Dec  3, 2025 06:28:07.419621000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.79**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 91.199.163.12->10.128.239.57:3389, 10.128.239.57->91.199.163.12:54990, 147.45.112.188->10.128.239.57:3389, 10.128.239.57->147.45.112.188:30081, 10.128.239.57->193.3.19.42:28398, 45.227.254.152->10.128.239.57:3389, 10.128.239.57->45.227.254.152:48731
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
  - [tls_analysis] suspicious_tls = 91.199.163.12->10.128.239.57:3389 (score=0.50) details={'entity': '91.199.163.12->10.128.239.57:3389', 'src_ip': '91.199.163.12', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 1, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Dec  3, 2025 07:02:13.933736000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.199.163.12:54990 (score=0.60) details={'entity': '10.128.239.57->91.199.163.12:54990', 'src_ip': '10.128.239.57', 'dst_ip': '91.199.163.12', 'dst_port': 54990, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  3, 2025 07:02:13.996119000 +08'}
  - [tls_analysis] suspicious_tls = 147.45.112.188->10.128.239.57:3389 (score=0.50) details={'entity': '147.45.112.188->10.128.239.57:3389', 'src_ip': '147.45.112.188', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 1, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Dec  3, 2025 07:02:14.064649000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->147.45.112.188:30081 (score=0.60) details={'entity': '10.128.239.57->147.45.112.188:30081', 'src_ip': '10.128.239.57', 'dst_ip': '147.45.112.188', 'dst_port': 30081, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  3, 2025 07:02:14.182431000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->193.3.19.42:28398 (score=0.60) details={'entity': '10.128.239.57->193.3.19.42:28398', 'src_ip': '10.128.239.57', 'dst_ip': '193.3.19.42', 'dst_port': 28398, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  3, 2025 07:02:14.241530000 +08'}
  - [tls_analysis] suspicious_tls = 45.227.254.152->10.128.239.57:3389 (score=0.50) details={'entity': '45.227.254.152->10.128.239.57:3389', 'src_ip': '45.227.254.152', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 1, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Dec  3, 2025 07:02:14.613014000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.227.254.152:48731 (score=0.60) details={'entity': '10.128.239.57->45.227.254.152:48731', 'src_ip': '10.128.239.57', 'dst_ip': '45.227.254.152', 'dst_port': 48731, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 4, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec  3, 2025 07:02:14.775735000 +08'}

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

- 2026-04-12T14:54:40.926080Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:40.926327Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:40.926504Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:40.926506Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:40.926554Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:40.926567Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:40.926576Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:40.926612Z | materialize_findings | Generated 2 final findings