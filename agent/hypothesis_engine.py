from agent.models import Hypothesis


def upsert_hypothesis(result, title, description, severity, evidence):
    existing = None
    for hyp in result.hypotheses.values():
        if hyp.title == title:
            existing = hyp
            break

    if existing is None:
        hyp_id = f"HYP-{len(result.hypotheses) + 1:03d}"
        result.hypotheses[hyp_id] = Hypothesis(
            hypothesis_id=hyp_id,
            title=title,
            description=description,
            severity=severity,
            evidence=[evidence],
            entities=[str(evidence.details.get("entity", evidence.value))],
        )
    else:
        existing.evidence.append(evidence)
        entity = str(evidence.details.get("entity", evidence.value))
        if entity not in existing.entities:
            existing.entities.append(entity)


def score_hypotheses(result, config):
    for hyp in result.hypotheses.values():
        if not hyp.evidence:
            hyp.confidence = 0.0
            hyp.guardrail_flags.append("no_evidence")
            hyp.human_review_required = True
            hyp.missed_detection_risks.append("No evidence available to score this hypothesis reliably.")
            continue

        evidence_scores = [ev.score for ev in hyp.evidence]
        avg_score = sum(evidence_scores) / len(evidence_scores)
        corroboration_bonus = min(0.20, 0.05 * max(0, len(hyp.evidence) - 1))
        diversity_bonus = min(0.10, 0.05 * (len(set(ev.source for ev in hyp.evidence)) - 1))
        severity_bonus = {
            "LOW": 0.00,
            "MEDIUM": 0.03,
            "HIGH": 0.05,
            "CRITICAL": 0.08,
        }.get(hyp.severity, 0.0)

        hyp.confidence = round(min(1.0, avg_score + corroboration_bonus + diversity_bonus + severity_bonus), 3)


def _attach_uncertainty_annotations(hyp):
    if hyp.title == "Suspicious DNS Activity":
        hyp.false_positive_risks.extend([
            "High-entropy DNS can also appear in CDNs, telemetry, security products, and benign service-generated domains.",
            "Repeated subdomain variation is suspicious but does not alone prove DNS tunneling.",
        ])
        hyp.missed_detection_risks.extend([
            "Low-volume DNS covert channels may stay below threshold.",
            "Benign-looking domains used by attackers may evade entropy-based heuristics.",
        ])
        hyp.limitations.extend([
            "DNS classification relies on metadata and naming patterns rather than payload semantics.",
        ])

    elif hyp.title == "Suspicious HTTP C2":
        hyp.false_positive_risks.extend([
            "Automation tools, scripts, and internal APIs may use unusual user agents or long URIs legitimately.",
        ])
        hyp.missed_detection_risks.extend([
            "HTTPS-encrypted application-layer content is not visible through this HTTP heuristic.",
            "Well-disguised malware using normal browsers and short URIs may evade detection.",
        ])
        hyp.limitations.extend([
            "HTTP logic is metadata-driven and does not inspect decrypted content.",
        ])

    elif hyp.title == "Suspicious TLS Session":
        hyp.false_positive_risks.extend([
            "Missing SNI may occur in privacy-focused or legacy environments and is not inherently malicious.",
            "TLS on non-standard ports is suspicious but can still be legitimate.",
        ])
        hyp.missed_detection_risks.extend([
            "If JA3 is unavailable, TLS detections rely on weaker metadata signals.",
            "Encrypted malicious traffic with normal TLS fingerprints may not be flagged.",
        ])
        hyp.limitations.extend([
            "TLS analysis may be constrained by unavailable JA3, limited SNI visibility, or incomplete handshake metadata.",
        ])

    elif hyp.title == "C2 Beaconing":
        hyp.false_positive_risks.extend([
            "Periodic communications can also come from software updates, health checks, backup tools, or monitoring agents.",
        ])
        hyp.missed_detection_risks.extend([
            "Jittered beaconing designed to avoid regular intervals may not be detected.",
            "Sparse beaconing with too few repetitions may stay below the threshold.",
        ])
        hyp.limitations.extend([
            "Beaconing analysis is timing-based and does not validate payload intent.",
        ])

    elif hyp.title == "Known Bad IP Communication":
        hyp.false_positive_risks.extend([
            "Threat intelligence feeds may be stale, noisy, or context-dependent.",
        ])
        hyp.missed_detection_risks.extend([
            "Malicious infrastructure not present in the configured bad-IP list will not be caught by reputation alone.",
        ])
        hyp.limitations.extend([
            "IP reputation is only as strong as the configured intelligence source and update cadence.",
        ])

    elif hyp.title == "Possible Data Exfiltration":
        hyp.false_positive_risks.extend([
            "Multiple suspicious signals from one host may still reflect layered benign automation rather than exfiltration.",
        ])
        hyp.missed_detection_risks.extend([
            "Actual exfiltration may occur over channels not covered by current heuristics.",
        ])
        hyp.limitations.extend([
            "This is a correlation-based inference, not direct proof of content theft or data transfer.",
        ])

    elif hyp.title == "SMB Lateral Movement":
        hyp.false_positive_risks.extend([
            "Legitimate IT management tools, vulnerability scanners, and backup software may scan SMB ports.",
            "Network discovery protocols in enterprise environments can produce similar patterns.",
        ])
        hyp.missed_detection_risks.extend([
            "Slow, targeted lateral movement that stays below scan thresholds may not be detected.",
        ])
        hyp.limitations.extend([
            "SMB analysis relies on connection metadata and cannot inspect file-level operations.",
        ])

    elif hyp.title == "External Sensitive Access":
        hyp.false_positive_risks.extend([
            "Legitimate remote administration via RDP or SSH from authorized external IPs.",
            "VPN or jump-host traffic may appear as external access.",
        ])
        hyp.missed_detection_risks.extend([
            "Access via VPN tunnels that terminate internally will not appear as external.",
        ])
        hyp.limitations.extend([
            "Cannot distinguish between authorized and unauthorized remote access without credential context.",
        ])

    elif hyp.title == "Potential Data Exfiltration":
        hyp.false_positive_risks.extend([
            "Large legitimate uploads (backups, cloud sync, CI/CD) may trigger volumetric thresholds.",
        ])
        hyp.missed_detection_risks.extend([
            "Slow, low-volume exfiltration may stay below detection thresholds.",
            "Encrypted exfiltration via legitimate services may not be flagged.",
        ])
        hyp.limitations.extend([
            "Volumetric analysis detects transfer patterns, not content — payload inspection requires decryption.",
        ])

    elif hyp.title == "Multi-Signal Threat":
        hyp.false_positive_risks.extend([
            "A host with multiple benign anomalies may still be flagged by correlation.",
        ])
        hyp.missed_detection_risks.extend([
            "Attacks using only one communication channel will not trigger multi-signal correlation.",
        ])
        hyp.limitations.extend([
            "Correlation strength depends on the quality and coverage of upstream analyzers.",
        ])


def apply_guardrails(result, config):
    for hyp in result.hypotheses.values():
        evidence_count = len(hyp.evidence)
        source_count = len(set(ev.source for ev in hyp.evidence))

        if evidence_count < config.min_evidence_items:
            hyp.confidence = min(hyp.confidence, 0.49)
            hyp.guardrail_flags.append("insufficient_evidence")
            hyp.human_review_required = True
            result.notes.append(
                f"Guardrail applied to {hyp.hypothesis_id} ({hyp.title}): insufficient corroborating evidence."
            )

        if source_count < 2:
            hyp.guardrail_flags.append("limited_source_diversity")

        if hyp.confidence >= config.min_confidence_to_report and evidence_count < 3:
            hyp.guardrail_flags.append("reportable_but_thin_evidence")
            hyp.human_review_required = True

        if hyp.title in {"Possible Data Exfiltration", "Known Bad IP Communication"} and hyp.confidence >= 0.60:
            hyp.guardrail_flags.append("high_impact_claim_requires_human_validation")
            hyp.human_review_required = True

        if hyp.confidence < config.min_confidence_to_report:
            hyp.guardrail_flags.append("below_reporting_threshold")

        _attach_uncertainty_annotations(hyp)

    result.safety_controls.append({
        "control": "minimum_evidence_requirement",
        "description": f"Hypotheses with fewer than {config.min_evidence_items} evidence items are downgraded below formal reporting threshold.",
    })
    result.safety_controls.append({
        "control": "confidence_threshold_for_reporting",
        "description": f"Only hypotheses with confidence >= {config.min_confidence_to_report} are materialized as findings.",
    })
    result.safety_controls.append({
        "control": "human_review_for_high_impact_or_thin_claims",
        "description": "Potentially high-impact findings and thinly corroborated claims are flagged for analyst validation before operational use.",
    })
    result.safety_controls.append({
        "control": "source_diversity_tracking",
        "description": "Hypotheses record whether evidence came from limited or multiple analytic sources.",
    })

    result.investigation_limitations.extend([
        "This investigation uses network-derived evidence only and has no host-level telemetry.",
        "Some detections rely on protocol metadata and heuristics rather than full semantic reconstruction.",
        "Encrypted traffic may reduce visibility into true intent or content.",
        "Threshold-based logic can reduce false positives but may also reduce recall.",
    ])