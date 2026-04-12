# Agentic Network Forensic Report — bundle_2025-12-17_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2025-12-17_nested_overlap` and identified **2 reportable finding(s)**. The highest-confidence finding was **Suspicious DNS Activity** with confidence **1.00** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 163
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
- Affected Entities: 10.128.239.171:us-v20.events.data.microsoft.com, 10.128.239.20:us-v20.events.data.microsoft.com
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
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=0.90) details={'entity': '10.128.239.171:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.171', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.941, 'query_count': 3, 'base_domain_count': 3, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec 17, 2025 20:52:08.588924000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=0.90) details={'entity': '10.128.239.171:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.171', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '28', 'entropy': 3.941, 'query_count': 3, 'base_domain_count': 3, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec 17, 2025 20:52:08.646226000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=0.90) details={'entity': '10.128.239.20:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.941, 'query_count': 3, 'base_domain_count': 3, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec 17, 2025 20:52:08.705888000 +08'}

### 2. Suspicious TLS Session
- Severity: **MEDIUM**
- Confidence: **0.83**
- MITRE ATT&CK: T1573, T1071
- Description: Suspicious TLS metadata suggests encrypted malicious communication.
- Recommendation: Review certificate, SNI, JA3, and destination context; block suspicious encrypted channels pending verification.
- Affected Entities: 10.128.239.57->141.98.83.10:51994, 10.128.239.57->179.60.146.36:60950, 10.128.239.57->141.98.83.10:51340, 10.128.239.57->98.159.33.100:10385, 10.128.239.57->91.238.181.6:43463, 10.128.239.57->179.60.146.35:57485, 10.128.239.57->91.238.181.8:36312, 45.135.232.19->10.128.239.57:3389, 10.128.239.57->45.135.232.19:41921, 10.128.239.57->80.75.212.45:29451, 141.98.11.170->10.128.239.57:3389, 10.128.239.57->141.98.11.170:21025, 10.128.239.57->136.144.42.225:1231, 10.128.239.57->141.98.83.10:56475
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
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.83.10:51994 (score=0.60) details={'entity': '10.128.239.57->141.98.83.10:51994', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.83.10', 'dst_port': 51994, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 09:42:44.027172000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.36:60950 (score=0.60) details={'entity': '10.128.239.57->179.60.146.36:60950', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.36', 'dst_port': 60950, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 09:42:44.197550000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.83.10:51340 (score=0.60) details={'entity': '10.128.239.57->141.98.83.10:51340', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.83.10', 'dst_port': 51340, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 09:42:44.257682000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->98.159.33.100:10385 (score=0.60) details={'entity': '10.128.239.57->98.159.33.100:10385', 'src_ip': '10.128.239.57', 'dst_ip': '98.159.33.100', 'dst_port': 10385, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:31:36.087695000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.6:43463 (score=0.60) details={'entity': '10.128.239.57->91.238.181.6:43463', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.6', 'dst_port': 43463, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:31:36.259837000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->179.60.146.35:57485 (score=0.60) details={'entity': '10.128.239.57->179.60.146.35:57485', 'src_ip': '10.128.239.57', 'dst_ip': '179.60.146.35', 'dst_port': 57485, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:52:07.706801000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->91.238.181.8:36312 (score=0.60) details={'entity': '10.128.239.57->91.238.181.8:36312', 'src_ip': '10.128.239.57', 'dst_ip': '91.238.181.8', 'dst_port': 36312, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:52:07.818762000 +08'}
  - [tls_analysis] suspicious_tls = 45.135.232.19->10.128.239.57:3389 (score=0.50) details={'entity': '45.135.232.19->10.128.239.57:3389', 'src_ip': '45.135.232.19', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 1, 'reasons': ['missing_sni', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:52:07.885293000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->45.135.232.19:41921 (score=0.60) details={'entity': '10.128.239.57->45.135.232.19:41921', 'src_ip': '10.128.239.57', 'dst_ip': '45.135.232.19', 'dst_port': 41921, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:52:07.945004000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->80.75.212.45:29451 (score=0.60) details={'entity': '10.128.239.57->80.75.212.45:29451', 'src_ip': '10.128.239.57', 'dst_ip': '80.75.212.45', 'dst_port': 29451, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:52:08.235729000 +08'}
  - [tls_analysis] suspicious_tls = 141.98.11.170->10.128.239.57:3389 (score=0.70) details={'entity': '141.98.11.170->10.128.239.57:3389', 'src_ip': '141.98.11.170', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '16', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'unusual_handshake_type', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:55:32.620737000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.170:21025 (score=0.60) details={'entity': '10.128.239.57->141.98.11.170:21025', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.170', 'dst_port': 21025, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:55:32.681532000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->136.144.42.225:1231 (score=0.60) details={'entity': '10.128.239.57->136.144.42.225:1231', 'src_ip': '10.128.239.57', 'dst_ip': '136.144.42.225', 'dst_port': 1231, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:55:32.896258000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.83.10:56475 (score=0.60) details={'entity': '10.128.239.57->141.98.83.10:56475', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.83.10', 'dst_port': 56475, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:55:33.064639000 +08'}
  - [tls_analysis] suspicious_tls = 141.98.11.170->10.128.239.57:3389 (score=0.60) details={'entity': '141.98.11.170->10.128.239.57:3389', 'src_ip': '141.98.11.170', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:55:33.126733000 +08'}
  - [tls_analysis] suspicious_tls = 10.128.239.57->141.98.11.170:21025 (score=0.60) details={'entity': '10.128.239.57->141.98.11.170:21025', 'src_ip': '10.128.239.57', 'dst_ip': '141.98.11.170', 'dst_port': 21025, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 13, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:55:33.202796000 +08'}
  - [tls_analysis] suspicious_tls = 141.98.11.170->10.128.239.57:3389 (score=0.60) details={'entity': '141.98.11.170->10.128.239.57:3389', 'src_ip': '141.98.11.170', 'dst_ip': '10.128.239.57', 'dst_port': 3389, 'ja3': '', 'sni': '', 'handshake_type': '', 'handshake_version': '', 'record_version': '', 'missing_sni_count_for_src': 3, 'reasons': ['missing_sni', 'repeated_missing_sni_from_source', 'tls_on_nonstandard_port', 'low_metadata_visibility'], 'event_timestamp': 'Dec 17, 2025 20:55:33.409966000 +08'}

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

- 2026-04-12T14:54:41.031220Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:41.031503Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:41.031585Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:41.031587Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:41.031667Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:41.031682Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:41.031693Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:41.031717Z | materialize_findings | Generated 2 final findings