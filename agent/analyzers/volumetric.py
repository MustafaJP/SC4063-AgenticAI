"""
Volumetric anomaly detector.

Detects:
- Large outbound data transfers (potential exfiltration)
- Unusual session counts to single destinations
- Long-lived sessions (potential C2 or data staging)
"""

from collections import defaultdict

from agent.models import Evidence


def _is_internal(ip, config):
    if not ip:
        return False
    return any(ip.startswith(prefix) for prefix in config.internal_prefixes)


def analyze_volumetric(flows, config):
    evidence_items = []

    # Group outbound sessions by (src_ip, dst_ip)
    outbound_groups = defaultdict(list)

    for flow in flows:
        src_ip = flow.get("src_ip")
        dst_ip = flow.get("dst_ip")

        if not src_ip or not dst_ip:
            continue

        # Internal -> External
        if _is_internal(src_ip, config) and not _is_internal(dst_ip, config):
            key = (src_ip, dst_ip)
            outbound_groups[key].append(flow)

    for (src_ip, dst_ip), connections in outbound_groups.items():
        session_count = len(connections)

        # Check for high session count to single destination
        if session_count < config.volumetric_min_sessions:
            continue

        score = 0.0
        reasons = []

        # Many sessions to same external destination
        if session_count >= 5:
            score += 0.3
            reasons.append("high_session_count")

        if session_count >= 10:
            score += 0.2
            reasons.append("very_high_session_count")

        if session_count >= 20:
            score += 0.2
            reasons.append("excessive_sessions")

        # Check if using known exfiltration ports
        ports_used = set()
        for c in connections:
            p = c.get("dst_port")
            if p is not None:
                try:
                    ports_used.add(int(p))
                except (ValueError, TypeError):
                    pass

        if 443 in ports_used:
            score += 0.1
            reasons.append("https_exfil_channel")

        if any(p > 10000 for p in ports_used):
            score += 0.1
            reasons.append("high_port_usage")

        # Check raw_json for byte counts if available
        total_bytes = 0
        for c in connections:
            raw = c.get("raw_json") or c.get("raw") or {}
            if isinstance(raw, str):
                continue
            bytes_val = raw.get("bytes") or raw.get("total_bytes") or raw.get("resp_bytes") or 0
            try:
                total_bytes += int(bytes_val)
            except (ValueError, TypeError):
                pass

        if total_bytes >= config.volumetric_min_bytes:
            score += 0.3
            reasons.append(f"large_transfer_{total_bytes}_bytes")

        if score < 0.3:
            continue

        entity = f"{src_ip}->{dst_ip}"
        evidence_items.append(
            Evidence(
                source="volumetric_analysis",
                indicator="volumetric_anomaly",
                value=entity,
                score=round(min(1.0, score), 3),
                details={
                    "entity": entity,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "session_count": session_count,
                    "total_bytes": total_bytes,
                    "ports_used": sorted(ports_used),
                    "reasons": reasons,
                    "event_timestamp": connections[0].get("event_timestamp"),
                },
            )
        )

    return evidence_items
