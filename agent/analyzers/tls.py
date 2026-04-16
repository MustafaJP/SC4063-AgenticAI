from collections import Counter

from agent.models import Evidence


def analyze_tls(tls_events, config):
    evidence_items = []

    # Count repeated missing-SNI sessions by source host
    missing_sni_by_src = Counter()
    for session in tls_events:
        raw = session.get("raw_json") or session.get("raw") or {}
        sni = str(raw.get("server_name") or raw.get("sni") or "").strip().lower()
        src_ip = session.get("src_ip", "unknown")

        if sni in {"", "unknown", "none"}:
            missing_sni_by_src[src_ip] += 1

    for session in tls_events:
        raw = session.get("raw_json") or session.get("raw") or {}

        ja3 = str(raw.get("ja3") or "").strip().lower()
        sni = str(raw.get("server_name") or raw.get("sni") or "").strip().lower()
        hs_type = str(raw.get("handshake_type") or "").strip()
        hs_version = str(raw.get("handshake_version") or "").strip()
        record_version = str(raw.get("record_version") or "").strip()

        src_ip = session.get("src_ip", "unknown")
        dst_ip = session.get("dst_ip", "unknown")
        dst_port = session.get("dst_port")

        score = 0.0
        reasons = []

        if ja3 and ja3 in config.known_risky_ja3:
            score += 0.7
            reasons.append("known_risky_ja3")

        if sni in {"", "unknown", "none"}:
            score += 0.2
            reasons.append("missing_sni")

        if missing_sni_by_src.get(src_ip, 0) >= 3:
            score += 0.2
            reasons.append("repeated_missing_sni_from_source")

        # Check if port is a known TLS-using service (RDP, LDAPS, etc.)
        dst_port_int = int(dst_port) if dst_port is not None else None
        is_known_tls_port = dst_port_int in config.tls_known_ports if dst_port_int else False

        if is_known_tls_port:
            # Known TLS services naturally lack SNI — skip flagging
            continue

        if dst_port not in (443, "443", None):
            score += 0.1
            reasons.append("tls_on_nonstandard_port")

        if hs_type and hs_type not in {"1", "2"}:
            score += 0.1
            reasons.append("unusual_handshake_type")

        if not ja3 and sni in {"", "unknown", "none"} and dst_port not in (443, "443", None):
            score += 0.1
            reasons.append("low_metadata_visibility")

        if score >= 0.5:
            entity = f"{src_ip}->{dst_ip}:{dst_port}"
            evidence_items.append(
                Evidence(
                    source="tls_analysis",
                    indicator="suspicious_tls",
                    value=ja3 or entity,
                    score=round(min(score, 1.0), 3),
                    details={
                        "entity": entity,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "ja3": ja3,
                        "sni": sni,
                        "handshake_type": hs_type,
                        "handshake_version": hs_version,
                        "record_version": record_version,
                        "missing_sni_count_for_src": missing_sni_by_src.get(src_ip, 0),
                        "reasons": reasons,
                        "event_timestamp": session.get("event_timestamp"),
                    },
                )
            )

    return evidence_items