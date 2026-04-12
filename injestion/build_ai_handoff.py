import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from registry import EvidenceRegistry


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def safe_bundle_id(parse_group: str) -> str:
    clean = parse_group.replace(" ", "_").replace("/", "_")
    return f"bundle_{clean}"


def summarize_pcaps(pcap_rows) -> Dict:
    durations = [r["capture_duration_seconds"] for r in pcap_rows if r["capture_duration_seconds"] is not None]
    packets = [r["capture_packet_count"] for r in pcap_rows if r["capture_packet_count"] is not None]

    overlap_counter = Counter(r["overlap_class"] for r in pcap_rows if r["overlap_class"])
    priority_counter = Counter(str(r["processing_priority"]) for r in pcap_rows if r["processing_priority"] is not None)

    return {
        "pcap_count": len(pcap_rows),
        "total_duration_seconds": round(sum(durations), 3) if durations else 0,
        "total_packets": int(sum(packets)) if packets else 0,
        "overlap_class_breakdown": dict(overlap_counter),
        "processing_priority_breakdown": dict(priority_counter),
    }


def summarize_events(event_rows) -> Dict:
    event_type_counter = Counter(r["event_type"] for r in event_rows if r["event_type"])
    app_proto_counter = Counter(r["app_proto"] for r in event_rows if r["app_proto"])

    src_counter = Counter(r["src_ip"] for r in event_rows if r["src_ip"])
    dst_counter = Counter(r["dst_ip"] for r in event_rows if r["dst_ip"])

    return {
        "event_count": len(event_rows),
        "event_type_breakdown": dict(event_type_counter),
        "app_proto_breakdown": dict(app_proto_counter),
        "top_src_ips": src_counter.most_common(10),
        "top_dst_ips": dst_counter.most_common(10),
    }


def build_pcap_section(pcap_rows) -> List[Dict]:
    pcaps = []
    for r in pcap_rows:
        pcaps.append({
            "pcap_id": r["pcap_id"],
            "filename": r["filename"],
            "full_path": r["full_path"],
            "sha256": r["sha256"],
            "capture_first_packet_time": r["capture_first_packet_time"],
            "capture_last_packet_time": r["capture_last_packet_time"],
            "capture_duration_seconds": r["capture_duration_seconds"],
            "capture_packet_count": r["capture_packet_count"],
            "capture_data_size_bytes": r["capture_data_size_bytes"],
            "capture_file_size_bytes": r["capture_file_size_bytes"],
            "capture_encapsulation": r["capture_encapsulation"],
            "time_bucket": r["time_bucket"],
            "overlap_class": r["overlap_class"],
            "processing_priority": r["processing_priority"],
            "parse_group": r["parse_group"],
        })
    return pcaps


def build_event_section(event_rows) -> List[Dict]:
    events = []
    for r in event_rows:
        parsed_raw = None
        try:
            parsed_raw = json.loads(r["raw_json"]) if r["raw_json"] else None
        except Exception:
            parsed_raw = {"raw_json_unparsed": r["raw_json"]}

        events.append({
            "event_id": r["event_id"],
            "pcap_id": r["pcap_id"],
            "chunk_id": r["chunk_id"],
            "task_id": r["task_id"],
            "event_type": r["event_type"],
            "event_timestamp": r["event_timestamp"],
            "src_ip": r["src_ip"],
            "dst_ip": r["dst_ip"],
            "src_port": r["src_port"],
            "dst_port": r["dst_port"],
            "network_proto": r["network_proto"],
            "app_proto": r["app_proto"],
            "summary": r["summary"],
            "raw_json": parsed_raw,
        })
    return events


def build_provenance(pcap_rows, event_rows) -> Dict:
    return {
        "generated_at": utc_now_iso(),
        "source_pcap_ids": [r["pcap_id"] for r in pcap_rows],
        "source_paths": [r["full_path"] for r in pcap_rows],
        "event_sources": sorted(list({r["task_id"] for r in event_rows if r["task_id"]})),
        "note": "Bundle created from normalized ingestion-layer outputs for downstream agentic analysis."
    }


def build_bundle(parse_group: str, time_bucket: str, pcap_rows, event_rows) -> Dict:
    return {
        "bundle_id": safe_bundle_id(parse_group),
        "time_bucket": time_bucket,
        "parse_group": parse_group,
        "stats": {
            "pcap_summary": summarize_pcaps(pcap_rows),
            "event_summary": summarize_events(event_rows),
        },
        "pcaps": build_pcap_section(pcap_rows),
        "events": build_event_section(event_rows),
        "provenance": build_provenance(pcap_rows, event_rows),
    }


def write_bundle(bundle: Dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = output_dir / f"{bundle['bundle_id']}.json"

    with bundle_path.open("w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)

    return bundle_path


def main(db_path: str, output_dir: str, clear_existing: bool, event_limit_per_group: int) -> None:
    registry = EvidenceRegistry(db_path=db_path)

    try:
        groups = registry.fetch_parse_groups()
        if not groups:
            print("[INFO] No parse groups found. Run Step 3 first.")
            return

        if clear_existing:
            registry.clear_step6_tables()
            print("[INFO] Cleared old AI handoff bundle records.")

        outdir = Path(output_dir).resolve()
        built = 0

        for g in groups:
            parse_group = g["parse_group"]
            time_bucket = g["time_bucket"]

            pcap_rows = registry.fetch_bundle_pcaps(parse_group)
            event_rows = registry.fetch_bundle_events(parse_group, limit=event_limit_per_group)

            if not pcap_rows:
                print(f"[SKIP] No PCAP rows for parse_group={parse_group}")
                continue

            bundle = build_bundle(parse_group, time_bucket, pcap_rows, event_rows)
            bundle_path = write_bundle(bundle, outdir)

            registry.insert_ai_handoff_bundle({
                "bundle_id": bundle["bundle_id"],
                "time_bucket": time_bucket,
                "parse_group": parse_group,
                "bundle_path": str(bundle_path),
                "pcap_count": len(pcap_rows),
                "event_count": len(event_rows),
                "bundle_status": "READY",
                "created_at": utc_now_iso(),
            })

            built += 1
            print(
                f"[OK] Built bundle {bundle['bundle_id']} | "
                f"pcaps={len(pcap_rows)} | events={len(event_rows)} | "
                f"path={bundle_path}"
            )

        print("\n=== STEP 6 COMPLETE ===")
        print(f"Bundles built: {built}")

    finally:
        registry.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build AI handoff bundles from normalized events and planning metadata."
    )
    parser.add_argument(
        "--db-path",
        default="evidence_registry.db",
        help="Path to SQLite registry database."
    )
    parser.add_argument(
        "--output-dir",
        default="ai_handoff_bundles",
        help="Directory where JSON bundles will be written."
    )
    parser.add_argument(
        "--clear-existing",
        action="store_true",
        help="Clear old bundle registry records before rebuilding."
    )
    parser.add_argument(
        "--event-limit-per-group",
        type=int,
        default=5000,
        help="Maximum number of normalized events to include per bundle."
    )
    args = parser.parse_args()

    main(
        db_path=args.db_path,
        output_dir=args.output_dir,
        clear_existing=args.clear_existing,
        event_limit_per_group=args.event_limit_per_group
    )