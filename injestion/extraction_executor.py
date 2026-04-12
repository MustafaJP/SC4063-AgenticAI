import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from registry import EvidenceRegistry


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    ts = ts.strip()
    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%b %d, %Y %H:%M:%S.%f",
        "%b %d, %Y %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def build_time_filter(capture_start: str, offset_start: float, offset_end: float) -> Optional[str]:
    base = parse_ts(capture_start)
    if base is None:
        return None

    start_ts = base + timedelta(seconds=float(offset_start))
    end_ts = base + timedelta(seconds=float(offset_end))

    start_epoch = start_ts.timestamp()
    end_epoch = end_ts.timestamp()

    return f"frame.time_epoch >= {start_epoch} && frame.time_epoch < {end_epoch}"


def tshark_fields(pcap_path: str, display_filter: Optional[str], fields: List[str]) -> List[List[str]]:
    cmd = ["tshark", "-r", pcap_path]

    if display_filter:
        cmd += ["-Y", display_filter]

    cmd += ["-T", "fields"]
    for f in fields:
        cmd += ["-e", f]

    cmd += ["-E", "separator=\t", "-E", "occurrence=f"]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"tshark failed: {stderr}")

    rows = []
    for line in result.stdout.splitlines():
        rows.append(line.split("\t"))
    return rows


def make_event_id(task_id: str, payload: Dict) -> str:
    digest = hashlib.sha256(
        (task_id + "|" + json.dumps(payload, sort_keys=True, default=str)).encode("utf-8")
    ).hexdigest()[:16]
    return f"{task_id}_{digest}"


def build_event_base(task_row, event_type: str, payload: Dict) -> Dict:
    return {
        "event_id": make_event_id(task_row["task_id"], payload),
        "pcap_id": task_row["pcap_id"],
        "chunk_id": task_row["chunk_id"],
        "task_id": task_row["task_id"],
        "event_type": event_type,
        "event_timestamp": payload.get("event_timestamp"),
        "src_ip": payload.get("src_ip"),
        "dst_ip": payload.get("dst_ip"),
        "src_port": payload.get("src_port"),
        "dst_port": payload.get("dst_port"),
        "network_proto": payload.get("network_proto"),
        "app_proto": payload.get("app_proto"),
        "summary": payload.get("summary"),
        "raw_json": json.dumps(payload, ensure_ascii=False),
        "created_at": utc_now_iso(),
    }


def run_flow_extractor(task_row) -> List[Dict]:
    time_filter = build_time_filter(
        task_row["capture_first_packet_time"],
        task_row["chunk_start_offset_seconds"],
        task_row["chunk_end_offset_seconds"]
    )

    display_filter = time_filter
    fields = [
        "frame.time",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "_ws.col.Protocol",
    ]

    rows = tshark_fields(task_row["full_path"], display_filter, fields)
    events = []

    for r in rows:
        r += [""] * (8 - len(r))
        ts, src_ip, dst_ip, tcp_s, tcp_d, udp_s, udp_d, proto = r[:8]

        src_port = tcp_s or udp_s or None
        dst_port = tcp_d or udp_d or None

        payload = {
            "event_timestamp": ts,
            "src_ip": src_ip or None,
            "dst_ip": dst_ip or None,
            "src_port": int(src_port) if src_port and src_port.isdigit() else None,
            "dst_port": int(dst_port) if dst_port and dst_port.isdigit() else None,
            "network_proto": "tcp" if tcp_s or tcp_d else ("udp" if udp_s or udp_d else None),
            "app_proto": proto or None,
            "summary": f"flow {src_ip}:{src_port} -> {dst_ip}:{dst_port} proto={proto}",
        }
        events.append(build_event_base(task_row, "flow", payload))

    return events


def run_dns_extractor(task_row) -> List[Dict]:
    time_filter = build_time_filter(
        task_row["capture_first_packet_time"],
        task_row["chunk_start_offset_seconds"],
        task_row["chunk_end_offset_seconds"]
    )

    display_filter = f"({time_filter}) && dns" if time_filter else "dns"
    fields = [
        "frame.time",
        "ip.src",
        "ip.dst",
        "dns.qry.name",
        "dns.qry.type",
        "dns.a",
    ]

    rows = tshark_fields(task_row["full_path"], display_filter, fields)
    events = []

    for r in rows:
        r += [""] * (6 - len(r))
        ts, src_ip, dst_ip, qry_name, qry_type, dns_a = r[:6]

        payload = {
            "event_timestamp": ts,
            "src_ip": src_ip or None,
            "dst_ip": dst_ip or None,
            "network_proto": "udp",
            "app_proto": "dns",
            "query_name": qry_name or None,
            "query_type": qry_type or None,
            "answer": dns_a or None,
            "summary": f"dns query={qry_name} type={qry_type} answer={dns_a}",
        }
        events.append(build_event_base(task_row, "dns", payload))

    return events


def run_http_extractor(task_row) -> List[Dict]:
    time_filter = build_time_filter(
        task_row["capture_first_packet_time"],
        task_row["chunk_start_offset_seconds"],
        task_row["chunk_end_offset_seconds"]
    )

    display_filter = f"({time_filter}) && http" if time_filter else "http"
    fields = [
        "frame.time",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.user_agent",
    ]

    rows = tshark_fields(task_row["full_path"], display_filter, fields)
    events = []

    for r in rows:
        r += [""] * (9 - len(r))
        ts, src_ip, dst_ip, src_port, dst_port, method, host, uri, ua = r[:9]

        if not method and not host and not uri:
            continue

        payload = {
            "event_timestamp": ts,
            "src_ip": src_ip or None,
            "dst_ip": dst_ip or None,
            "src_port": int(src_port) if src_port and src_port.isdigit() else None,
            "dst_port": int(dst_port) if dst_port and dst_port.isdigit() else None,
            "network_proto": "tcp",
            "app_proto": "http",
            "method": method or None,
            "host": host or None,
            "uri": uri or None,
            "user_agent": ua or None,
            "summary": f"http {method or 'UNKNOWN'} http://{host or ''}{uri or ''}",
        }
        events.append(build_event_base(task_row, "http", payload))

    return events


def run_tls_extractor(task_row) -> List[Dict]:
    time_filter = build_time_filter(
        task_row["capture_first_packet_time"],
        task_row["chunk_start_offset_seconds"],
        task_row["chunk_end_offset_seconds"]
    )

    display_filter = f"({time_filter}) && tls" if time_filter else "tls"
    fields = [
        "frame.time",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tls.handshake.extensions_server_name",
        "tls.handshake.type",
    ]

    rows = tshark_fields(task_row["full_path"], display_filter, fields)
    events = []

    for r in rows:
        r += [""] * (7 - len(r))
        ts, src_ip, dst_ip, src_port, dst_port, sni, hs_type = r[:7]

        payload = {
            "event_timestamp": ts,
            "src_ip": src_ip or None,
            "dst_ip": dst_ip or None,
            "src_port": int(src_port) if src_port and src_port.isdigit() else None,
            "dst_port": int(dst_port) if dst_port and dst_port.isdigit() else None,
            "network_proto": "tcp",
            "app_proto": "tls",
            "sni": sni or None,
            "handshake_type": hs_type or None,
            "summary": f"tls session sni={sni} type={hs_type}",
        }
        events.append(build_event_base(task_row, "tls", payload))

    return events


def run_ioc_extractor(task_row) -> List[Dict]:
    events = []

    dns_events = run_dns_extractor(task_row)
    for event in dns_events:
        raw = json.loads(event["raw_json"])
        q = (raw.get("query_name") or "").lower()
        if any(x in q for x in ["update", "cdn", "login", "verify", "secure"]) and len(q) > 25:
            payload = {
                "event_timestamp": raw.get("event_timestamp"),
                "src_ip": raw.get("src_ip"),
                "dst_ip": raw.get("dst_ip"),
                "network_proto": raw.get("network_proto"),
                "app_proto": "ioc",
                "indicator_type": "suspicious_domain_pattern",
                "indicator_value": q,
                "summary": f"ioc suspicious domain pattern: {q}",
            }
            events.append(build_event_base(task_row, "ioc", payload))

    tls_events = run_tls_extractor(task_row)
    for event in tls_events:
        raw = json.loads(event["raw_json"])
        sni = (raw.get("sni") or "").lower()
        if sni and any(x in sni for x in ["login", "verify", "auth", "secure"]):
            payload = {
                "event_timestamp": raw.get("event_timestamp"),
                "src_ip": raw.get("src_ip"),
                "dst_ip": raw.get("dst_ip"),
                "network_proto": raw.get("network_proto"),
                "app_proto": "ioc",
                "indicator_type": "suspicious_sni_pattern",
                "indicator_value": sni,
                "summary": f"ioc suspicious sni pattern: {sni}",
            }
            events.append(build_event_base(task_row, "ioc", payload))

    return events


def run_timeline_extractor(task_row) -> List[Dict]:
    flow_events = run_flow_extractor(task_row)
    events = []

    for ev in flow_events[:500]:
        raw = json.loads(ev["raw_json"])
        payload = {
            "event_timestamp": raw.get("event_timestamp"),
            "src_ip": raw.get("src_ip"),
            "dst_ip": raw.get("dst_ip"),
            "src_port": raw.get("src_port"),
            "dst_port": raw.get("dst_port"),
            "network_proto": raw.get("network_proto"),
            "app_proto": "timeline",
            "summary": f"timeline event {raw.get('src_ip')}:{raw.get('src_port')} -> {raw.get('dst_ip')}:{raw.get('dst_port')}",
        }
        events.append(build_event_base(task_row, "timeline", payload))

    return events


EXTRACTOR_MAP = {
    "flow": run_flow_extractor,
    "dns": run_dns_extractor,
    "http": run_http_extractor,
    "tls": run_tls_extractor,
    "ioc": run_ioc_extractor,
    "timeline": run_timeline_extractor,
}


def execute_task(registry: EvidenceRegistry, task_row) -> None:
    task_id = task_row["task_id"]
    task_type = task_row["task_type"]

    registry.update_task_status(task_id, "RUNNING")

    run_id = registry.insert_task_run({
        "task_id": task_id,
        "pcap_id": task_row["pcap_id"],
        "chunk_id": task_row["chunk_id"],
        "task_type": task_type,
        "run_started_at": utc_now_iso(),
        "run_status": "RUNNING",
        "records_written": 0,
        "error_message": "",
    })

    try:
        extractor = EXTRACTOR_MAP.get(task_type)
        if extractor is None:
            raise RuntimeError(f"No extractor registered for task type: {task_type}")

        events = extractor(task_row)

        for ev in events:
            registry.insert_normalized_event(ev)

        registry.update_task_status(task_id, "SUCCESS")
        registry.update_task_run(
            run_id=run_id,
            run_finished_at=utc_now_iso(),
            run_status="SUCCESS",
            records_written=len(events),
            error_message=""
        )

        print(f"[OK] {task_id} | {task_type} | wrote {len(events)} events")

    except Exception as e:
        registry.update_task_status(task_id, "FAILED")
        registry.update_task_run(
            run_id=run_id,
            run_finished_at=utc_now_iso(),
            run_status="FAILED",
            records_written=0,
            error_message=str(e)
        )
        print(f"[FAIL] {task_id} | {task_type} | {e}")


def main(db_path: str, limit: Optional[int] = None, task_types: Optional[List[str]] = None) -> None:
    registry = EvidenceRegistry(db_path=db_path)

    try:
        if task_types:
            tasks = registry.fetch_planned_tasks_by_types(task_types=task_types, limit=limit)
        else:
            tasks = registry.fetch_planned_tasks(limit=limit)

        if not tasks:
            print("[INFO] No planned tasks found.")
            return

        print(f"[INFO] Executing {len(tasks)} planned tasks")
        if task_types:
            print(f"[INFO] Task-type filter enabled: {task_types}")
        if limit is None:
            print("[INFO] No limit provided. Running full planned set.")

        for task in tasks:
            execute_task(registry, task)

        print("\n=== EXTRACTION COMPLETE ===")
        print(f"Tasks attempted: {len(tasks)}")

    finally:
        registry.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Execute planned extraction tasks and write normalized outputs."
    )
    parser.add_argument(
        "--db-path",
        default="evidence_registry.db",
        help="Path to SQLite registry database."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional maximum number of planned tasks to execute. If omitted, runs all planned tasks."
    )
    parser.add_argument(
        "--task-types",
        nargs="+",
        choices=["flow", "dns", "http", "tls", "ioc", "timeline"],
        help="Optional list of task types to execute."
    )
    args = parser.parse_args()

    main(
        db_path=args.db_path,
        limit=args.limit,
        task_types=args.task_types
    )