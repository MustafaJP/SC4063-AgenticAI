from agent.models import Evidence


def analyze_http(http_events, config):
    evidence_items = []

    for req in http_events:
        raw = req.get("raw_json") or req.get("raw") or {}
        ua = str(raw.get("user_agent") or raw.get("ua") or "").lower()
        host = str(raw.get("host") or raw.get("http_host") or "").lower()
        uri = str(raw.get("uri") or raw.get("path") or "")
        method = str(raw.get("method") or raw.get("http_method") or "GET").upper()
        src_ip = req.get("src_ip", "unknown")

        score = 0.0
        reasons = []

        if any(keyword in ua for keyword in config.suspicious_ua_keywords):
            score += 0.5
            reasons.append("suspicious_user_agent")
        if len(uri) > 120:
            score += 0.2
            reasons.append("long_uri")
        if method not in {"GET", "POST", "HEAD"}:
            score += 0.2
            reasons.append("unusual_method")
        if host.count(".") >= 4:
            score += 0.1
            reasons.append("deep_subdomain")

        if score >= 0.5:
            entity = f"{src_ip}:{host}{uri}"
            evidence_items.append(
                Evidence(
                    source="http_analysis",
                    indicator="suspicious_http",
                    value=f"{host}{uri}",
                    score=round(min(score, 1.0), 3),
                    details={
                        "entity": entity,
                        "src_ip": src_ip,
                        "host": host,
                        "uri": uri,
                        "method": method,
                        "user_agent": ua,
                        "reasons": reasons,
                        "event_timestamp": req.get("event_timestamp"),
                    },
                )
            )

    return evidence_items