import statistics
from collections import defaultdict

from agent.models import Evidence


def _to_float_timestamp(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)

    text = str(value).strip()
    if not text:
        return None

    try:
        return float(text)
    except Exception:
        pass

    # ISO timestamp support
    try:
        from datetime import datetime
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except Exception:
        pass

    # Wireshark-style timestamp: "Dec  3, 2025 06:28:07.160439000 +08"
    import re
    from datetime import datetime, timezone, timedelta

    # Normalize multiple spaces to single
    normalized = re.sub(r"\s+", " ", text).strip()

    # Try common Wireshark formats
    wireshark_patterns = [
        # "Dec  3, 2025 06:28:07.160439000 +08"
        (r"^(\w{3}) (\d{1,2}), (\d{4}) (\d{2}:\d{2}:\d{2})\.(\d+) ([+-]\d{2})$", True),
        # "Dec  3, 2025 06:28:07 +08"
        (r"^(\w{3}) (\d{1,2}), (\d{4}) (\d{2}:\d{2}:\d{2}) ([+-]\d{2})$", False),
        # Without timezone
        (r"^(\w{3}) (\d{1,2}), (\d{4}) (\d{2}:\d{2}:\d{2})\.(\d+)$", True),
        (r"^(\w{3}) (\d{1,2}), (\d{4}) (\d{2}:\d{2}:\d{2})$", False),
    ]

    months = {
        "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
        "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
    }

    for pattern, has_frac in wireshark_patterns:
        m = re.match(pattern, normalized)
        if not m:
            continue
        try:
            groups = m.groups()
            month = months.get(groups[0].lower())
            if not month:
                continue
            day = int(groups[1])
            year = int(groups[2])
            time_parts = groups[3].split(":")
            hour, minute, second = int(time_parts[0]), int(time_parts[1]), int(time_parts[2])
            microsecond = 0
            tz_offset = None

            idx = 4
            if has_frac:
                frac_str = groups[idx][:6].ljust(6, "0")
                microsecond = int(frac_str)
                idx += 1

            if idx < len(groups) and groups[idx]:
                tz_hours = int(groups[idx])
                tz_offset = timezone(timedelta(hours=tz_hours))

            dt = datetime(year, month, day, hour, minute, second, microsecond,
                          tzinfo=tz_offset or timezone.utc)
            return dt.timestamp()
        except Exception:
            continue

    return None


def analyze_beaconing(flows, config):
    """
    Detect periodic communications that may indicate beaconing.

    Expected input:
    - flows: list of normalized events, usually all events from the bundle
    - config: AgentConfig

    Detection logic:
    - group by src_ip, dst_ip, dst_port, protocol
    - require minimum repeated observations
    - compute intervals between timestamps
    - low deviation relative to average interval => more periodic => higher score
    """
    evidence_items = []
    grouped = defaultdict(list)

    for flow in flows:
        src_ip = flow.get("src_ip")
        dst_ip = flow.get("dst_ip")
        dst_port = flow.get("dst_port") or flow.get("src_port")
        proto = flow.get("network_proto") or flow.get("proto") or flow.get("app_proto")

        ts = (
            flow.get("event_timestamp")
            or flow.get("timestamp")
            or flow.get("ts")
        )
        ts_float = _to_float_timestamp(ts)

        if not src_ip or not dst_ip or ts_float is None:
            continue

        key = (src_ip, dst_ip, dst_port, proto)
        grouped[key].append({
            "ts": ts_float,
            "event_timestamp": flow.get("event_timestamp") or flow.get("timestamp") or flow.get("ts"),
            "raw": flow,
        })

    for key, observations in grouped.items():
        if len(observations) < config.beacon_min_repeats:
            continue

        observations = sorted(observations, key=lambda x: x["ts"])
        timestamps = [x["ts"] for x in observations]
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

        if not intervals:
            continue

        avg_interval = statistics.mean(intervals)
        deviation = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0

        periodicity_score = 0.0
        if avg_interval > 0:
            periodicity_score = max(0.0, 1.0 - (deviation / avg_interval))

        if periodicity_score < config.beacon_periodicity_threshold:
            continue

        src_ip, dst_ip, dst_port, proto = key
        entity = f"{src_ip}->{dst_ip}:{dst_port}/{proto}"

        evidence_items.append(
            Evidence(
                source="beaconing_analysis",
                indicator="periodic_communication",
                value=entity,
                score=round(min(1.0, periodicity_score), 3),
                details={
                    "entity": entity,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "proto": proto,
                    "avg_interval": round(avg_interval, 2),
                    "deviation": round(deviation, 2),
                    "count": len(observations),
                    "first_seen": observations[0]["event_timestamp"],
                    "last_seen": observations[-1]["event_timestamp"],
                    "event_timestamp": observations[0]["event_timestamp"],
                },
            )
        )

    return evidence_items