import argparse
import hashlib
import json
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def run_ioc_extractor(task_row, dns_cache=None, tls_cache=None) -> List[Dict]:
    """
    IOC extractor that reuses cached DNS/TLS results instead of re-running tshark.
    """
    events = []

    # Reuse cached DNS events or extract fresh
    dns_events = dns_cache if dns_cache is not None else run_dns_extractor(task_row)
    for event in dns_events:
        raw = json.loads(event["raw_json"]) if isinstance(event["raw_json"], str) else event["raw_json"]
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

    # Reuse cached TLS events or extract fresh
    tls_events = tls_cache if tls_cache is not None else run_tls_extractor(task_row)
    for event in tls_events:
        raw = json.loads(event["raw_json"]) if isinstance(event["raw_json"], str) else event["raw_json"]
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


def run_timeline_extractor(task_row, flow_cache=None) -> List[Dict]:
    """
    Timeline extractor that reuses cached flow results instead of re-running tshark.
    """
    flow_events = flow_cache if flow_cache is not None else run_flow_extractor(task_row)
    events = []

    for ev in flow_events[:500]:
        raw = json.loads(ev["raw_json"]) if isinstance(ev["raw_json"], str) else ev["raw_json"]
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


def batch_insert_events(registry: EvidenceRegistry, events: List[Dict]) -> None:
    """Insert multiple events in a single transaction instead of one commit per event."""
    if not events:
        return
    cur = registry.conn.cursor()
    for ev in events:
        cur.execute("""
        INSERT OR REPLACE INTO normalized_events (
            event_id, pcap_id, chunk_id, task_id, event_type,
            event_timestamp, src_ip, dst_ip, src_port, dst_port,
            network_proto, app_proto, summary, raw_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ev["event_id"], ev["pcap_id"], ev["chunk_id"], ev["task_id"],
            ev["event_type"], ev.get("event_timestamp"), ev.get("src_ip"),
            ev.get("dst_ip"), ev.get("src_port"), ev.get("dst_port"),
            ev.get("network_proto"), ev.get("app_proto"), ev.get("summary"),
            ev.get("raw_json"), ev["created_at"],
        ))
    registry.conn.commit()


def execute_chunk_batch(registry: EvidenceRegistry, chunk_tasks: List) -> None:
    """
    Execute all tasks for a single chunk in one batch.

    This eliminates redundant tshark calls by:
    1. Running flow/dns/http/tls extractors first (each = 1 tshark call)
    2. Passing cached results to ioc and timeline extractors (0 tshark calls)

    Result: 4 tshark calls per chunk instead of 7.
    """
    if not chunk_tasks:
        return

    # Build a lookup of task_type -> task_row for this chunk
    task_by_type = {}
    for task in chunk_tasks:
        task_by_type[task["task_type"]] = task

    # Shared reference task (all tasks in a chunk share pcap/chunk info)
    ref_task = chunk_tasks[0]

    # Run primary extractors and cache results
    cached = {}
    primary_types = ["flow", "dns", "http", "tls"]

    for task_type in primary_types:
        if task_type not in task_by_type:
            continue

        task_row = task_by_type[task_type]
        task_id = task_row["task_id"]

        registry.update_task_status(task_id, "RUNNING")
        run_id = registry.insert_task_run({
            "task_id": task_id, "pcap_id": task_row["pcap_id"],
            "chunk_id": task_row["chunk_id"], "task_type": task_type,
            "run_started_at": utc_now_iso(), "run_status": "RUNNING",
            "records_written": 0, "error_message": "",
        })

        try:
            extractor = EXTRACTOR_MAP[task_type]
            events = extractor(task_row)
            cached[task_type] = events

            batch_insert_events(registry, events)

            registry.update_task_status(task_id, "SUCCESS")
            registry.update_task_run(run_id, utc_now_iso(), "SUCCESS", len(events), "")
            print(f"[OK] {task_id} | {task_type} | wrote {len(events)} events")
        except Exception as e:
            cached[task_type] = []
            registry.update_task_status(task_id, "FAILED")
            registry.update_task_run(run_id, utc_now_iso(), "FAILED", 0, str(e))
            print(f"[FAIL] {task_id} | {task_type} | {e}")

    # Run derived extractors using cached data (NO extra tshark calls)
    derived_types = {
        "ioc": lambda tr: run_ioc_extractor(
            tr, dns_cache=cached.get("dns", []), tls_cache=cached.get("tls", [])
        ),
        "timeline": lambda tr: run_timeline_extractor(
            tr, flow_cache=cached.get("flow", [])
        ),
    }

    for task_type, extractor_fn in derived_types.items():
        if task_type not in task_by_type:
            continue

        task_row = task_by_type[task_type]
        task_id = task_row["task_id"]

        registry.update_task_status(task_id, "RUNNING")
        run_id = registry.insert_task_run({
            "task_id": task_id, "pcap_id": task_row["pcap_id"],
            "chunk_id": task_row["chunk_id"], "task_type": task_type,
            "run_started_at": utc_now_iso(), "run_status": "RUNNING",
            "records_written": 0, "error_message": "",
        })

        try:
            events = extractor_fn(task_row)
            batch_insert_events(registry, events)

            registry.update_task_status(task_id, "SUCCESS")
            registry.update_task_run(run_id, utc_now_iso(), "SUCCESS", len(events), "")
            print(f"[OK] {task_id} | {task_type} | wrote {len(events)} events (cached)")
        except Exception as e:
            registry.update_task_status(task_id, "FAILED")
            registry.update_task_run(run_id, utc_now_iso(), "FAILED", 0, str(e))
            print(f"[FAIL] {task_id} | {task_type} | {e}")


def execute_task(registry: EvidenceRegistry, task_row) -> None:
    """Legacy single-task executor (used when tasks aren't grouped by chunk)."""
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
        batch_insert_events(registry, events)

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


def main(db_path: str, limit: Optional[int] = None, task_types: Optional[List[str]] = None,
         workers: int = 1) -> None:
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

        # Group tasks by chunk_id so we can batch and reuse cached results
        chunks = defaultdict(list)
        for task in tasks:
            chunks[task["chunk_id"]].append(task)

        print(f"[INFO] Grouped into {len(chunks)} chunks (eliminates redundant tshark calls)")

        if workers > 1:
            # Parallel execution: one chunk per worker thread
            # Note: each thread gets its own DB connection to avoid SQLite threading issues
            print(f"[INFO] Using {workers} parallel workers")

            def process_chunk(chunk_id, chunk_tasks):
                thread_registry = EvidenceRegistry(db_path=db_path)
                try:
                    execute_chunk_batch(thread_registry, chunk_tasks)
                finally:
                    thread_registry.close()

            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {}
                for chunk_id, chunk_tasks in chunks.items():
                    future = executor.submit(process_chunk, chunk_id, chunk_tasks)
                    futures[future] = chunk_id

                for future in as_completed(futures):
                    chunk_id = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        print(f"[FAIL] Chunk {chunk_id} failed: {e}")
        else:
            # Sequential execution with chunk batching
            for chunk_id, chunk_tasks in chunks.items():
                execute_chunk_batch(registry, chunk_tasks)

        print("\n=== EXTRACTION COMPLETE ===")
        print(f"Tasks attempted: {len(tasks)}")
        print(f"Chunks processed: {len(chunks)}")

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
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of parallel workers for chunk processing. Default 1 (sequential)."
    )
    args = parser.parse_args()

    main(
        db_path=args.db_path,
        limit=args.limit,
        task_types=args.task_types,
        workers=args.workers,
    )
