# Agentic Network Forensic Report — bundle_2025-12-06_nested_overlap

## Executive Summary

The autonomous forensic agent analyzed structured evidence for `bundle_2025-12-06_nested_overlap` and identified **1 reportable finding(s)**. The highest-confidence finding was **Suspicious DNS Activity** with confidence **1.00** and severity **MEDIUM**.

## Analysis Metrics

- Event Count: 39
- PCAP Count: 1
- Hypothesis Count: 1
- Finding Count: 1
- Analysis Runtime (seconds): 0.0
- Estimated Analysis Cost: 0.0
- Human Review Required Count: 0
- Guardrailed Hypothesis Count: 1

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
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=0.90) details={'entity': '10.128.239.171:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.171', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.941, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec  6, 2025 01:03:26.714351000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=0.90) details={'entity': '10.128.239.171:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.171', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '28', 'entropy': 3.941, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec  6, 2025 01:03:26.772436000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=0.90) details={'entity': '10.128.239.20:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '28', 'entropy': 3.941, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec  6, 2025 01:03:26.839250000 +08'}
  - [dns_analysis] high_entropy_dns = us-v20.events.data.microsoft.com (score=0.90) details={'entity': '10.128.239.20:us-v20.events.data.microsoft.com', 'src_ip': '10.128.239.20', 'query': 'us-v20.events.data.microsoft.com', 'base_domain': 'microsoft.com', 'qtype': '1', 'entropy': 3.941, 'query_count': 4, 'base_domain_count': 4, 'host_count_for_query': 2, 'host_count_for_base_domain': 2, 'varying_subdomain_count': 1, 'reasons': ['high_entropy', 'repeated_domain', 'multi_host_domain'], 'event_timestamp': 'Dec  6, 2025 01:03:26.904619000 +08'}

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

- 2026-04-12T14:54:40.949509Z | review_summary | Started summary-first investigation
- 2026-04-12T14:54:40.949611Z | analyze_beaconing | Completed beaconing analysis
- 2026-04-12T14:54:40.949712Z | analyze_dns | Completed DNS analysis
- 2026-04-12T14:54:40.949715Z | analyze_http | Completed HTTP analysis
- 2026-04-12T14:54:40.949732Z | analyze_tls | Completed TLS analysis
- 2026-04-12T14:54:40.949738Z | analyze_bad_ip_reputation | Completed IP reputation analysis
- 2026-04-12T14:54:40.949744Z | cross_signal_correlation | Completed cross-signal correlation
- 2026-04-12T14:54:40.949764Z | materialize_findings | Generated 1 final findings