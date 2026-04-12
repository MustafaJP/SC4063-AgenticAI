import argparse
from registry import EvidenceRegistry


def main(db_path: str) -> None:
    registry = EvidenceRegistry(db_path=db_path)
    try:
        print("\n=== AGENT QUERY AUDIT ===\n")
        for row in registry.fetch_agent_query_audit(limit=50):
            print(
                f"id={row['query_id']} | "
                f"type={row['query_type']} | "
                f"bundle={row['bundle_id']} | "
                f"results={row['result_count']} | "
                f"time={row['query_timestamp']} | "
                f"text={row['query_text']}"
            )
    finally:
        registry.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="View agent query audit log.")
    parser.add_argument("--db-path", default="evidence_registry.db")
    args = parser.parse_args()
    main(args.db_path)