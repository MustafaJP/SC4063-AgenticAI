import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_bundle(bundle_path: Path) -> Dict[str, Any]:
    with bundle_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def top_counter(values, n=10):
    return Counter(v for v in values if v).most_common(n)


def summarize_bundle(bundle: Dict[str, Any]) -> Dict[str, Any]:
    events = bundle.get("events", [])
    pcaps = bundle.get("pcaps", [])
    stats = bundle.get("stats", {})

    event_type_top = top_counter([e.get("event_type") for e in events], 10)
    app_proto_top = top_counter([e.get("app_proto") for e in events], 10)
    src_ip_top = top_counter([e.get("src_ip") for e in events], 10)
    dst_ip_top = top_counter([e.get("dst_ip") for e in events], 10)

    domain_hits = []
    suspicious_hits = []

    for e in events:
        raw = e.get("raw") or {}
        if raw.get("query_name"):
            domain_hits.append(raw.get("query_name"))
        if raw.get("host"):
            domain_hits.append(raw.get("host"))
        if raw.get("sni"):
            domain_hits.append(raw.get("sni"))

        summary = (e.get("summary") or "").lower()
        if any(x in summary for x in ["ioc", "suspicious", "verify", "auth", "secure", "login"]):
            suspicious_hits.append({
                "event_id": e.get("event_id"),
                "event_type": e.get("event_type"),
                "event_timestamp": e.get("event_timestamp"),
                "summary": e.get("summary"),
            })

    suspicious_hits = suspicious_hits[:25]
    domain_top = top_counter(domain_hits, 15)

    earliest = None
    latest = None
    timeline_preview = []

    sorted_events = sorted(
        events,
        key=lambda x: (x.get("event_timestamp") or "", x.get("event_id") or "")
    )

    if sorted_events:
        earliest = sorted_events[0].get("event_timestamp")
        latest = sorted_events[-1].get("event_timestamp")
        timeline_preview = [
            {
                "event_timestamp": e.get("event_timestamp"),
                "event_type": e.get("event_type"),
                "summary": e.get("summary"),
            }
            for e in sorted_events[:50]
        ]

    return {
        "bundle_id": bundle.get("bundle_id"),
        "time_bucket": bundle.get("time_bucket"),
        "parse_group": bundle.get("parse_group"),
        "summary_generated_at": utc_now_iso(),
        "bundle_stats": stats,
        "overview": {
            "pcap_count": len(pcaps),
            "event_count": len(events),
            "earliest_event_timestamp": earliest,
            "latest_event_timestamp": latest,
        },
        "top_entities": {
            "event_types": event_type_top,
            "application_protocols": app_proto_top,
            "top_src_ips": src_ip_top,
            "top_dst_ips": dst_ip_top,
            "top_domains_or_names": domain_top,
        },
        "suspicious_highlights": suspicious_hits,
        "timeline_preview": timeline_preview,
        "provenance": bundle.get("provenance", {}),
    }


def build_retrieval_docs(bundle: Dict[str, Any], summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    docs = []

    bundle_id = bundle.get("bundle_id")
    parse_group = bundle.get("parse_group")
    time_bucket = bundle.get("time_bucket")

    overview = summary.get("overview", {})
    top_entities = summary.get("top_entities", {})
    suspicious = summary.get("suspicious_highlights", [])
    timeline_preview = summary.get("timeline_preview", [])

    docs.append({
        "doc_id": f"{bundle_id}_overview",
        "bundle_id": bundle_id,
        "parse_group": parse_group,
        "time_bucket": time_bucket,
        "doc_type": "overview",
        "text": (
            f"Bundle {bundle_id} for parse group {parse_group} in bucket {time_bucket}. "
            f"PCAP count {overview.get('pcap_count')}. "
            f"Event count {overview.get('event_count')}. "
            f"Earliest event {overview.get('earliest_event_timestamp')}. "
            f"Latest event {overview.get('latest_event_timestamp')}."
        )
    })

    docs.append({
        "doc_id": f"{bundle_id}_entities",
        "bundle_id": bundle_id,
        "parse_group": parse_group,
        "time_bucket": time_bucket,
        "doc_type": "entities",
        "text": (
            f"Top event types: {top_entities.get('event_types')}. "
            f"Top application protocols: {top_entities.get('application_protocols')}. "
            f"Top source IPs: {top_entities.get('top_src_ips')}. "
            f"Top destination IPs: {top_entities.get('top_dst_ips')}. "
            f"Top domains or names: {top_entities.get('top_domains_or_names')}."
        )
    })

    for idx, item in enumerate(suspicious[:20], start=1):
        docs.append({
            "doc_id": f"{bundle_id}_suspicious_{idx:03d}",
            "bundle_id": bundle_id,
            "parse_group": parse_group,
            "time_bucket": time_bucket,
            "doc_type": "suspicious_highlight",
            "text": (
                f"Suspicious highlight {idx}. "
                f"Timestamp {item.get('event_timestamp')}. "
                f"Type {item.get('event_type')}. "
                f"Summary {item.get('summary')}."
            )
        })

    for idx, item in enumerate(timeline_preview[:20], start=1):
        docs.append({
            "doc_id": f"{bundle_id}_timeline_{idx:03d}",
            "bundle_id": bundle_id,
            "parse_group": parse_group,
            "time_bucket": time_bucket,
            "doc_type": "timeline_preview",
            "text": (
                f"Timeline preview {idx}. "
                f"Timestamp {item.get('event_timestamp')}. "
                f"Type {item.get('event_type')}. "
                f"Summary {item.get('summary')}."
            )
        })

    return docs


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def main(db_path: str, summary_dir: str, retrieval_dir: str, clear_existing: bool) -> None:
    from registry import EvidenceRegistry

    registry = EvidenceRegistry(db_path=db_path)

    try:
        bundles = registry.fetch_ready_bundles()
        if not bundles:
            print("[INFO] No READY bundles found. Run Step 6 first.")
            return

        if clear_existing:
            registry.clear_step7_tables()
            print("[INFO] Cleared old Step 7 summary registry records.")

        summary_root = Path(summary_dir).resolve()
        retrieval_root = Path(retrieval_dir).resolve()

        built = 0

        for row in bundles:
            bundle_id = row["bundle_id"]
            parse_group = row["parse_group"]
            bundle_path = Path(row["bundle_path"])

            if not bundle_path.exists():
                print(f"[SKIP] Missing bundle file: {bundle_path}")
                continue

            bundle = load_bundle(bundle_path)
            summary = summarize_bundle(bundle)
            retrieval_docs = build_retrieval_docs(bundle, summary)

            summary_path = summary_root / f"{bundle_id}_summary.json"
            retrieval_path = retrieval_root / f"{bundle_id}_retrieval.json"

            write_json(summary_path, summary)
            write_json(retrieval_path, retrieval_docs)

            registry.insert_ai_bundle_summary({
                "bundle_id": bundle_id,
                "parse_group": parse_group,
                "summary_path": str(summary_path),
                "retrieval_path": str(retrieval_path),
                "event_count": len(bundle.get("events", [])),
                "summary_status": "READY",
                "created_at": utc_now_iso(),
            })

            built += 1
            print(
                f"[OK] Built pre-AI summary for {bundle_id} | "
                f"summary={summary_path} | retrieval={retrieval_path}"
            )

        print("\n=== STEP 7 COMPLETE ===")
        print(f"Pre-AI summaries built: {built}")

    finally:
        registry.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build pre-AI summaries and retrieval docs from AI handoff bundles."
    )
    parser.add_argument(
        "--db-path",
        default="evidence_registry.db",
        help="Path to SQLite registry database."
    )
    parser.add_argument(
        "--summary-dir",
        default="preai_summaries",
        help="Directory for summary JSON files."
    )
    parser.add_argument(
        "--retrieval-dir",
        default="preai_retrieval",
        help="Directory for retrieval JSON files."
    )
    parser.add_argument(
        "--clear-existing",
        action="store_true",
        help="Clear old Step 7 registry records before rebuilding."
    )
    args = parser.parse_args()

    main(
        db_path=args.db_path,
        summary_dir=args.summary_dir,
        retrieval_dir=args.retrieval_dir,
        clear_existing=args.clear_existing
    )