import argparse
import math
from datetime import datetime, timezone
from typing import Dict, List

from registry import EvidenceRegistry


BASE_TASKS = ["flow", "dns", "http", "tls", "ioc", "timeline"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def choose_chunk_strategy(duration_seconds, packet_count, overlap_class):
    duration_seconds = duration_seconds or 0
    packet_count = packet_count or 0

    if duration_seconds <= 3600 and packet_count <= 100_000:
        return "single_chunk", 1

    if duration_seconds <= 6 * 3600 and packet_count <= 500_000:
        return "balanced_chunking", 3

    if overlap_class == "EXACT_TIME_DUPLICATE":
        return "deferred_duplicate", 1

    if duration_seconds <= 24 * 3600 and packet_count <= 1_000_000:
        return "hourly_chunking", 6

    if duration_seconds <= 7 * 24 * 3600 and packet_count <= 5_000_000:
        return "dense_chunking", 12

    return "heavy_chunking", 24


def choose_task_list(overlap_class, processing_priority):
    if overlap_class == "EXACT_TIME_DUPLICATE":
        return ["timeline", "ioc"]

    if processing_priority == 1:
        return ["flow", "dns", "http", "tls", "ioc", "timeline"]

    if overlap_class in ("NESTED_OVERLAP", "OVERLAP_CANDIDATE"):
        return ["flow", "dns", "tls", "ioc", "timeline", "http"]

    return BASE_TASKS.copy()


def estimate_chunk_stats(total_packets, total_bytes, chunk_count, chunk_index):
    if not total_packets and not total_bytes:
        return None, None

    est_packets = math.ceil(total_packets / chunk_count) if total_packets else None
    est_bytes = math.ceil(total_bytes / chunk_count) if total_bytes else None
    return est_packets, est_bytes


def build_chunks_for_row(row) -> List[Dict]:
    pcap_id = row["pcap_id"]
    duration = row["capture_duration_seconds"] or 0
    packet_count = row["capture_packet_count"] or 0
    byte_count = row["capture_data_size_bytes"] or row["capture_file_size_bytes"] or 0
    overlap_class = row["overlap_class"]

    strategy, chunk_count = choose_chunk_strategy(duration, packet_count, overlap_class)

    if duration <= 0:
        chunk_count = 1
        duration = 1

    chunk_size = duration / chunk_count
    created_at = utc_now_iso()

    chunks = []
    for idx in range(chunk_count):
        start_offset = round(idx * chunk_size, 6)
        end_offset = round((idx + 1) * chunk_size, 6)

        if idx == chunk_count - 1:
            end_offset = duration

        est_packets, est_bytes = estimate_chunk_stats(packet_count, byte_count, chunk_count, idx)

        chunks.append({
            "chunk_id": f"{pcap_id}_chunk_{idx + 1:03d}",
            "pcap_id": pcap_id,
            "chunk_index": idx + 1,
            "chunk_start_offset_seconds": start_offset,
            "chunk_end_offset_seconds": end_offset,
            "estimated_packets": est_packets,
            "estimated_bytes": est_bytes,
            "chunk_strategy": strategy,
            "created_at": created_at
        })

    return chunks


def build_tasks_for_chunk(row, chunk_record) -> List[Dict]:
    pcap_id = row["pcap_id"]
    overlap_class = row["overlap_class"]
    processing_priority = row["processing_priority"]
    tasks = choose_task_list(overlap_class, processing_priority)

    created_at = utc_now_iso()
    task_records = []

    base_priority = processing_priority

    for idx, task_type in enumerate(tasks):
        task_priority = base_priority * 10 + idx + 1

        task_records.append({
            "task_id": f"{chunk_record['chunk_id']}_{task_type}",
            "pcap_id": pcap_id,
            "chunk_id": chunk_record["chunk_id"],
            "task_type": task_type,
            "task_priority": task_priority,
            "task_status": "PLANNED",
            "planner_notes": (
                f"group={row['parse_group']}; "
                f"class={overlap_class}; "
                f"pcap_priority={processing_priority}; "
                f"chunk_strategy={chunk_record['chunk_strategy']}"
            ),
            "created_at": created_at
        })

    return task_records


def main(db_path: str, clear_existing: bool) -> None:
    registry = EvidenceRegistry(db_path=db_path)

    try:
        rows = registry.fetch_processing_plan_rows()
        if not rows:
            print("[INFO] No processing-plan rows found. Run Step 3 first.")
            return

        if clear_existing:
            registry.clear_step4_tables()
            print("[INFO] Cleared old chunk plan and extraction task plan tables.")

        total_chunks = 0
        total_tasks = 0

        for row in rows:
            chunks = build_chunks_for_row(row)
            for chunk in chunks:
                registry.insert_chunk_plan(chunk)
                total_chunks += 1

                tasks = build_tasks_for_chunk(row, chunk)
                for task in tasks:
                    registry.insert_extraction_task(task)
                    total_tasks += 1

        print("\n=== STEP 4 COMPLETE ===")
        print(f"PCAPs planned: {len(rows)}")
        print(f"Chunks created: {total_chunks}")
        print(f"Extraction tasks created: {total_tasks}")

    finally:
        registry.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build chunk plan and extraction task plan from processing plan."
    )
    parser.add_argument(
        "--db-path",
        default="evidence_registry.db",
        help="Path to SQLite registry database."
    )
    parser.add_argument(
        "--clear-existing",
        action="store_true",
        help="Clear old Step 4 tables before rebuilding."
    )
    args = parser.parse_args()

    main(db_path=args.db_path, clear_existing=args.clear_existing)