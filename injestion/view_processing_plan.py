import argparse
from registry import EvidenceRegistry


def main(db_path: str) -> None:
    registry = EvidenceRegistry(db_path=db_path)
    try:
        print("\n=== OVERLAP MAP ===\n")
        overlap_rows = registry.fetch_overlap_map()
        for row in overlap_rows:
            print(
                f"{row['pcap_id_1']} <-> {row['pcap_id_2']} | "
                f"{row['relation_type']} | "
                f"overlap_s={row['overlap_seconds']:.2f} | "
                f"r1={row['overlap_ratio_1']:.3f} | "
                f"r2={row['overlap_ratio_2']:.3f}"
            )

        print("\n=== PROCESSING PLAN ===\n")
        plan_rows = registry.fetch_processing_plan()
        for row in plan_rows:
            print(
                f"{row['pcap_id']} | "
                f"priority={row['processing_priority']} | "
                f"class={row['overlap_class']} | "
                f"group={row['parse_group']} | "
                f"bucket={row['time_bucket']}"
            )

    finally:
        registry.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="View overlap map and processing plan.")
    parser.add_argument("--db-path", default="evidence_registry.db")
    args = parser.parse_args()
    main(args.db_path)