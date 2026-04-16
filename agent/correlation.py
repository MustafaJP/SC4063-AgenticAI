from agent.models import Evidence


def correlate_multi_signal_hosts(result):
    source_scores = {}

    for hyp in result.hypotheses.values():
        for ev in hyp.evidence:
            src_ip = ev.details.get("src_ip")
            if not src_ip:
                continue

            if src_ip not in source_scores:
                source_scores[src_ip] = {"signals": set(), "score": 0.0}

            indicator_scores = {
                "high_entropy_dns": ("dns", 0.3),
                "suspicious_http": ("http", 0.3),
                "suspicious_tls": ("tls", 0.2),
                "periodic_communication": ("beaconing", 0.4),
                "bad_reputation_ip": ("intel", 0.4),
                "smb_lateral_scan": ("smb", 0.4),
                "epm_enumeration": ("smb", 0.3),
                "external_sensitive_access": ("external_access", 0.4),
                "volumetric_anomaly": ("volumetric", 0.3),
            }

            if ev.indicator in indicator_scores:
                signal_name, score_val = indicator_scores[ev.indicator]
                source_scores[src_ip]["signals"].add(signal_name)
                source_scores[src_ip]["score"] += score_val

    evidence_items = []
    for src_ip, data in source_scores.items():
        if len(data["signals"]) >= 2 and data["score"] >= 0.7:
            evidence_items.append(
                Evidence(
                    source="cross_signal_correlation",
                    indicator="multi_signal_host",
                    value=src_ip,
                    score=round(min(1.0, data["score"]), 3),
                    details={
                        "entity": src_ip,
                        "src_ip": src_ip,
                        "signals": sorted(data["signals"]),
                    },
                )
            )

    return evidence_items