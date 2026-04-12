import argparse
from registry import EvidenceRegistry


def main(db_path: str) -> None:
    registry = EvidenceRegistry(db_path=db_path)
    try:
        print("\n=== PRE-AI SUMMARY REGISTRY ===\n")
        rows = registry.fetch_ai_bundle_summaries()
        for row in rows:
            print(
                f"{row['bundle_id']} | "
                f"group={row['parse_group']} | "
                f"events={row['event_count']} | "
                f"status={row['summary_status']} | "
                f"summary={row['summary_path']} | "
                f"retrieval={row['retrieval_path']}"
            )
    finally:
        registry.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="View Step 7 pre-AI summaries.")
    parser.add_argument("--db-path", default="evidence_registry.db")
    args = parser.parse_args()
    main(args.db_path)