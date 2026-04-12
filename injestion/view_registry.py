import argparse
from registry import EvidenceRegistry


def main(db_path: str) -> None:
    registry = EvidenceRegistry(db_path=db_path)
    try:
        rows = registry.fetch_all()
        print(f"\nTotal records: {len(rows)}\n")
        for row in rows:
            print(
                f"{row['pcap_id']} | "
                f"{row['ingest_status']} | "
                f"{row['file_type']} | "
                f"{row['filename']} | "
                f"packets={row['capture_packet_count']} | "
                f"start={row['capture_first_packet_time']} | "
                f"end={row['capture_last_packet_time']}"
            )
    finally:
        registry.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="View evidence registry contents.")
    parser.add_argument("--db-path", default="evidence_registry.db")
    args = parser.parse_args()
    main(args.db_path)