import argparse
from registry import EvidenceRegistry


def main(db_path: str) -> None:
    registry = EvidenceRegistry(db_path=db_path)
    try:
        print("\n=== CHUNK PLAN ===\n")
        chunk_rows = registry.fetch_chunk_plan()
        for row in chunk_rows:
            print(
                f"{row['chunk_id']} | "
                f"{row['pcap_id']} | "
                f"idx={row['chunk_index']} | "
                f"{row['chunk_start_offset_seconds']}->{row['chunk_end_offset_seconds']} | "
                f"strategy={row['chunk_strategy']} | "
                f"est_packets={row['estimated_packets']}"
            )

        print("\n=== EXTRACTION TASK PLAN ===\n")
        task_rows = registry.fetch_extraction_tasks()
        for row in task_rows:
            print(
                f"{row['task_id']} | "
                f"{row['task_type']} | "
                f"priority={row['task_priority']} | "
                f"status={row['task_status']} | "
                f"chunk={row['chunk_id']}"
            )

    finally:
        registry.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="View chunk plan and extraction task plan.")
    parser.add_argument("--db-path", default="evidence_registry.db")
    args = parser.parse_args()
    main(args.db_path)