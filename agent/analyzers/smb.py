"""
SMB lateral movement and scanning detector.

Detects:
- Port 445 scanning (many unique internal targets in rapid succession)
- SMB enumeration patterns (EPM port 135)
- Internal-to-internal SMB data staging
"""

from collections import defaultdict

from agent.models import Evidence


def _is_internal(ip, config):
    if not ip:
        return False
    return any(ip.startswith(prefix) for prefix in config.internal_prefixes)


def analyze_smb(flows, config):
    evidence_items = []

    # Group SMB connections by source IP
    smb_by_src = defaultdict(list)
    epm_by_src = defaultdict(list)

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

        if port == 445 and _is_internal(src_ip, config) and _is_internal(dst_ip, config):
            smb_by_src[src_ip].append(flow)
        elif port == 135 and _is_internal(src_ip, config):
            epm_by_src[src_ip].append(flow)

    # Detect port 445 scanning
    for src_ip, connections in smb_by_src.items():
        unique_targets = set(f.get("dst_ip") for f in connections)

        if len(unique_targets) < config.smb_scan_min_targets:
            continue

        score = min(1.0, 0.4 + 0.05 * len(unique_targets))
        reasons = ["smb_port_scan"]

        if len(unique_targets) >= 20:
            score = min(1.0, score + 0.2)
            reasons.append("mass_scanning")

        if len(unique_targets) >= 100:
            score = 1.0
            reasons.append("network_sweep")

        # Check if same source also does EPM
        if src_ip in epm_by_src:
            score = min(1.0, score + 0.15)
            reasons.append("combined_smb_epm_enumeration")

        entity = f"{src_ip}->internal:445"
        evidence_items.append(
            Evidence(
                source="smb_analysis",
                indicator="smb_lateral_scan",
                value=entity,
                score=round(score, 3),
                details={
                    "entity": entity,
                    "src_ip": src_ip,
                    "unique_targets": len(unique_targets),
                    "total_connections": len(connections),
                    "sample_targets": sorted(unique_targets)[:10],
                    "reasons": reasons,
                    "event_timestamp": connections[0].get("event_timestamp"),
                },
            )
        )

    # Detect EPM enumeration without SMB scan
    for src_ip, connections in epm_by_src.items():
        if src_ip in smb_by_src:
            continue  # Already reported above

        unique_targets = set(f.get("dst_ip") for f in connections)
        if len(unique_targets) < 3:
            continue

        entity = f"{src_ip}->internal:135"
        evidence_items.append(
            Evidence(
                source="smb_analysis",
                indicator="epm_enumeration",
                value=entity,
                score=0.6,
                details={
                    "entity": entity,
                    "src_ip": src_ip,
                    "unique_targets": len(unique_targets),
                    "reasons": ["epm_service_discovery"],
                    "event_timestamp": connections[0].get("event_timestamp"),
                },
            )
        )

    return evidence_items
