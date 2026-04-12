import argparse
from registry import EvidenceRegistry


def main(db_path: str) -> None:
    registry = EvidenceRegistry(db_path=db_path)
    try:
        print("\n=== AI HANDOFF BUNDLES ===\n")
        rows = registry.fetch_ai_handoff_bundles()
        for row in rows:
            print(
                f"{row['bundle_id']} | "
                f"group={row['parse_group']} | "
                f"bucket={row['time_bucket']} | "
                f"pcaps={row['pcap_count']} | "
                f"events={row['event_count']} | "
                f"status={row['bundle_status']} | "
                f"path={row['bundle_path']}"
            )
    finally:
        registry.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="View AI handoff bundles.")
    parser.add_argument("--db-path", default="evidence_registry.db")
    args = parser.parse_args()
    main(args.db_path)