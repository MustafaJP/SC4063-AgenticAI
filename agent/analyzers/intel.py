from agent.models import Evidence


def analyze_bad_ip_reputation(flows, config):
    evidence_items = []

    for flow in flows:
        dst_ip = flow.get("dst_ip")
        if dst_ip in config.known_bad_ips:
            risk = config.known_bad_ips[dst_ip]
            evidence_items.append(
                Evidence(
                    source="intel_analysis",
                    indicator="bad_reputation_ip",
                    value=dst_ip,
                    score=round(risk, 3),
                    details={
                        "entity": dst_ip,
                        "src_ip": flow.get("src_ip"),
                        "dst_ip": dst_ip,
                        "dst_port": flow.get("dst_port"),
                        "proto": flow.get("network_proto") or flow.get("proto"),
                        "event_timestamp": flow.get("event_timestamp"),
                    },
                )
            )

    return evidence_items