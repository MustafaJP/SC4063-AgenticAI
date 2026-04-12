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

            if ev.indicator == "high_entropy_dns":
                source_scores[src_ip]["signals"].add("dns")
                source_scores[src_ip]["score"] += 0.3
            elif ev.indicator == "suspicious_http":
                source_scores[src_ip]["signals"].add("http")
                source_scores[src_ip]["score"] += 0.3
            elif ev.indicator == "suspicious_tls":
                source_scores[src_ip]["signals"].add("tls")
                source_scores[src_ip]["score"] += 0.2
            elif ev.indicator == "periodic_communication":
                source_scores[src_ip]["signals"].add("beaconing")
                source_scores[src_ip]["score"] += 0.4
            elif ev.indicator == "bad_reputation_ip":
                source_scores[src_ip]["signals"].add("intel")
                source_scores[src_ip]["score"] += 0.4

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