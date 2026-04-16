"""
External access detector.

Detects:
- External-to-internal RDP access (port 3389)
- External-to-internal SSH access (port 22)
- Unusual inbound connections from external IPs to sensitive ports
"""

from collections import defaultdict

from agent.models import Evidence


def _is_internal(ip, config):
    if not ip:
        return False
    return any(ip.startswith(prefix) for prefix in config.internal_prefixes)


SENSITIVE_PORTS = {
    3389: "RDP",
    22: "SSH",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    23: "Telnet",
    445: "SMB",
    135: "EPM",
    139: "NetBIOS",
}


def analyze_external_access(flows, config):
    evidence_items = []

    # Group by (external_src, internal_dst, port)
    access_groups = defaultdict(list)

    for flow in flows:
        src_ip = flow.get("src_ip")
        dst_ip = flow.get("dst_ip")
        dst_port = flow.get("dst_port")

        if not src_ip or not dst_ip:
            continue

        try:
            port = int(dst_port) if dst_port is not None else None
        except (ValueError, TypeError):
            port = None

        if port not in SENSITIVE_PORTS:
            continue

        # External -> Internal
        if not _is_internal(src_ip, config) and _is_internal(dst_ip, config):
            key = (src_ip, dst_ip, port)
            access_groups[key].append(flow)

    for (src_ip, dst_ip, port), connections in access_groups.items():
        service_name = SENSITIVE_PORTS.get(port, "unknown")

        score = 0.5
        reasons = [f"external_{service_name.lower()}_access"]

        # RDP from external is especially suspicious
        if port == 3389:
            score += 0.3
            reasons.append("external_rdp_inbound")

        # Multiple connections from same source increase suspicion
        if len(connections) >= 3:
            score += 0.1
            reasons.append("repeated_access")

        entity = f"{src_ip}->{dst_ip}:{port}"
        evidence_items.append(
            Evidence(
                source="external_access_analysis",
                indicator="external_sensitive_access",
                value=entity,
                score=round(min(1.0, score), 3),
                details={
                    "entity": entity,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": port,
                    "service": service_name,
                    "connection_count": len(connections),
                    "reasons": reasons,
                    "event_timestamp": connections[0].get("event_timestamp"),
                },
            )
        )

    return evidence_items
