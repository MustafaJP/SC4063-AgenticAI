import argparse
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

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


def canonical_pair(a: str, b: str) -> Tuple[str, str]:
    return tuple(sorted([a, b]))


def classify_relation(
    start1: datetime,
    end1: datetime,
    start2: datetime,
    end2: datetime
) -> Tuple[float, float, float, str]:
    latest_start = max(start1, start2)
    earliest_end = min(end1, end2)

    overlap_seconds = max(0.0, (earliest_end - latest_start).total_seconds())

    dur1 = max((end1 - start1).total_seconds(), 1.0)
    dur2 = max((end2 - start2).total_seconds(), 1.0)

    overlap_ratio_1 = overlap_seconds / dur1
    overlap_ratio_2 = overlap_seconds / dur2

    if start1 == start2 and end1 == end2:
        relation_type = "EXACT_TIME_DUPLICATE"
    elif overlap_seconds <= 0:
        relation_type = "NO_OVERLAP"
    elif start1 <= start2 and end1 >= end2:
        relation_type = "PCAP1_CONTAINS_PCAP2"
    elif start2 <= start1 and end2 >= end1:
        relation_type = "PCAP2_CONTAINS_PCAP1"
    else:
        relation_type = "PARTIAL_OVERLAP"

    return overlap_seconds, overlap_ratio_1, overlap_ratio_2, relation_type


def choose_overlap_class(relations: List[Dict]) -> str:
    if not relations:
        return "STANDALONE"

    relation_types = {r["relation_type"] for r in relations}

    if "EXACT_TIME_DUPLICATE" in relation_types:
        return "EXACT_TIME_DUPLICATE"
    if "PCAP1_CONTAINS_PCAP2" in relation_types or "PCAP2_CONTAINS_PCAP1" in relation_types:
        return "NESTED_OVERLAP"
    if "PARTIAL_OVERLAP" in relation_types:
        return "OVERLAP_CANDIDATE"

    return "STANDALONE"


def choose_priority(row, overlap_class: str) -> int:
    duration = row["capture_duration_seconds"] or 0
    packets = row["capture_packet_count"] or 0

    if overlap_class == "EXACT_TIME_DUPLICATE":
        return 5

    if duration > 7 * 24 * 3600 or packets > 1_000_000:
        return 1

    if overlap_class in ("NESTED_OVERLAP", "OVERLAP_CANDIDATE"):
        return 2

    if duration > 24 * 3600 or packets > 100_000:
        return 2

    return 3


def build_time_bucket(row) -> Optional[str]:
    start = parse_ts(row["capture_first_packet_time"])
    if not start:
        return None
    return start.strftime("%Y-%m-%d")


def build_parse_group(row, overlap_class: str) -> str:
    bucket = build_time_bucket(row) or "unknown_date"
    return f"{bucket}_{overlap_class.lower()}"


def build_notes(row, overlap_class: str, relation_count: int) -> str:
    packets = row["capture_packet_count"]
    duration = row["capture_duration_seconds"]

    parts = [
        f"class={overlap_class}",
        f"relations={relation_count}",
    ]

    if packets is not None:
        parts.append(f"packets={packets}")
    if duration is not None:
        parts.append(f"duration_s={duration}")

    return "; ".join(parts)


def prepare_rows(rows):
    """
    Parse timestamps once and keep only rows with usable time bounds.
    """
    prepared = []
    skipped = 0

    for row in rows:
        start = parse_ts(row["capture_first_packet_time"])
        end = parse_ts(row["capture_last_packet_time"])

        if not start or not end or end < start:
            skipped += 1
            continue

        prepared.append({
            "row": row,
            "pcap_id": row["pcap_id"],
            "start": start,
            "end": end,
        })

    prepared.sort(key=lambda x: (x["start"], x["end"], x["pcap_id"]))
    return prepared, skipped


def main(db_path: str, clear_existing: bool) -> None:
    registry = EvidenceRegistry(db_path=db_path)

    try:
        rows = registry.fetch_for_overlap_analysis()
        if not rows:
            print("[INFO] No metadata-ready PCAPs found for overlap analysis.")
            return

        if clear_existing:
            registry.clear_overlap_tables()
            print("[INFO] Cleared existing overlap map and processing plan tables.")

        prepared, skipped = prepare_rows(rows)
        if not prepared:
            print("[INFO] No valid timestamped PCAPs available for overlap analysis.")
            return

        relations_by_pcap: Dict[str, List[Dict]] = defaultdict(list)
        overlap_count = 0
        comparisons = 0

        # Optimized overlap scan:
        # rows are sorted by start time, so once next.start > current.end,
        # we can stop checking further rows for current.
        for i in range(len(prepared)):
            current = prepared[i]
            r1 = current["row"]
            start1 = current["start"]
            end1 = current["end"]

            for j in range(i + 1, len(prepared)):
                nxt = prepared[j]
                start2 = nxt["start"]

                # Early stop: no future rows can overlap current row
                if start2 > end1:
                    break

                r2 = nxt["row"]
                end2 = nxt["end"]
                comparisons += 1

                overlap_seconds, overlap_ratio_1, overlap_ratio_2, relation_type = classify_relation(
                    start1, end1, start2, end2
                )

                if relation_type == "NO_OVERLAP":
                    continue

                p1, p2 = canonical_pair(r1["pcap_id"], r2["pcap_id"])

                if p1 == r1["pcap_id"]:
                    start_1 = r1["capture_first_packet_time"]
                    end_1 = r1["capture_last_packet_time"]
                    start_2 = r2["capture_first_packet_time"]
                    end_2 = r2["capture_last_packet_time"]
                    ratio_1 = overlap_ratio_1
                    ratio_2 = overlap_ratio_2
                else:
                    start_1 = r2["capture_first_packet_time"]
                    end_1 = r2["capture_last_packet_time"]
                    start_2 = r1["capture_first_packet_time"]
                    end_2 = r1["capture_last_packet_time"]
                    ratio_1 = overlap_ratio_2
                    ratio_2 = overlap_ratio_1

                record = {
                    "pcap_id_1": p1,
                    "pcap_id_2": p2,
                    "start_1": start_1,
                    "end_1": end_1,
                    "start_2": start_2,
                    "end_2": end_2,
                    "overlap_seconds": overlap_seconds,
                    "overlap_ratio_1": ratio_1,
                    "overlap_ratio_2": ratio_2,
                    "relation_type": relation_type,
                    "created_at": utc_now_iso(),
                }

                registry.insert_overlap_record(record)
                overlap_count += 1

                relations_by_pcap[r1["pcap_id"]].append({
                    "other": r2["pcap_id"],
                    "relation_type": relation_type,
                    "overlap_seconds": overlap_seconds,
                })
                relations_by_pcap[r2["pcap_id"]].append({
                    "other": r1["pcap_id"],
                    "relation_type": relation_type,
                    "overlap_seconds": overlap_seconds,
                })

        for item in prepared:
            row = item["row"]
            pcap_id = row["pcap_id"]
            relations = relations_by_pcap.get(pcap_id, [])
            overlap_class = choose_overlap_class(relations)
            priority = choose_priority(row, overlap_class)
            time_bucket = build_time_bucket(row)
            parse_group = build_parse_group(row, overlap_class)
            notes = build_notes(row, overlap_class, len(relations))

            registry.insert_processing_plan({
                "pcap_id": pcap_id,
                "time_bucket": time_bucket,
                "overlap_class": overlap_class,
                "processing_priority": priority,
                "parse_group": parse_group,
                "planner_notes": notes,
                "created_at": utc_now_iso(),
            })

        print("\n=== STEP 3 COMPLETE (OPTIMIZED) ===")
        print(f"Metadata-ready PCAPs fetched: {len(rows)}")
        print(f"Valid timestamped PCAPs analyzed: {len(prepared)}")
        print(f"Rows skipped due to bad/missing timestamps: {skipped}")
        print(f"Pairwise comparisons actually performed: {comparisons}")
        print(f"Overlap relations created: {overlap_count}")
        print(f"Processing plan rows created: {len(prepared)}")

    finally:
        registry.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build overlap map and processing plan from PCAP metadata."
    )
    parser.add_argument(
        "--db-path",
        default="evidence_registry.db",
        help="Path to SQLite registry database."
    )
    parser.add_argument(
        "--clear-existing",
        action="store_true",
        help="Clear old overlap and processing-plan tables before rebuilding."
    )
    args = parser.parse_args()

    main(db_path=args.db_path, clear_existing=args.clear_existing)