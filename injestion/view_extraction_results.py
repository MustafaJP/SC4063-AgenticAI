import argparse
from registry import EvidenceRegistry


def main(db_path: str) -> None:
    registry = EvidenceRegistry(db_path=db_path)
    try:
        print("\n=== TASK RUNS ===\n")
        for row in registry.fetch_task_runs(limit=50):
            print(
                f"run_id={row['run_id']} | "
                f"task_id={row['task_id']} | "
                f"type={row['task_type']} | "
                f"status={row['run_status']} | "
                f"records={row['records_written']}"
            )

        print("\n=== NORMALIZED EVENTS ===\n")
        for row in registry.fetch_normalized_events(limit=50):
            print(
                f"{row['event_id']} | "
                f"{row['event_type']} | "
                f"{row['event_timestamp']} | "
                f"{row['summary']}"
            )

    finally:
        registry.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="View Step 5 extraction results.")
    parser.add_argument("--db-path", default="evidence_registry.db")
    args = parser.parse_args()
    main(args.db_path)