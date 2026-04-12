import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

from injestion.registry import EvidenceRegistry


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: str) -> Any:
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


class AgentInterface:
    def __init__(self, db_path: str = "evidence_registry.db") -> None:
        self.registry = EvidenceRegistry(db_path=db_path)

    def close(self) -> None:
        self.registry.close()

    def list_bundles(self) -> List[Dict[str, Any]]:
        rows = self.registry.fetch_ai_handoff_bundles()
        result = [
            {
                "bundle_id": row["bundle_id"],
                "time_bucket": row["time_bucket"],
                "parse_group": row["parse_group"],
                "pcap_count": row["pcap_count"],
                "event_count": row["event_count"],
                "bundle_status": row["bundle_status"],
                "bundle_path": row["bundle_path"],
            }
            for row in rows
        ]

        self.registry.insert_agent_query_audit({
            "query_type": "list_bundles",
            "query_text": "",
            "bundle_id": None,
            "filters_json": "{}",
            "result_count": len(result),
            "query_timestamp": utc_now_iso()
        })
        return result

    def get_bundle_summary(self, bundle_id: str) -> Dict[str, Any]:
        rows = self.registry.fetch_ai_bundle_summaries()
        row = next((r for r in rows if r["bundle_id"] == bundle_id), None)
        if row is None:
            raise ValueError(f"Bundle summary not found for bundle_id={bundle_id}")

        summary = load_json(row["summary_path"])

        self.registry.insert_agent_query_audit({
            "query_type": "get_bundle_summary",
            "query_text": "",
            "bundle_id": bundle_id,
            "filters_json": "{}",
            "result_count": 1,
            "query_timestamp": utc_now_iso()
        })
        return summary

    def search_retrieval_docs(
        self,
        bundle_id: str,
        query_text: str,
        max_results: int = 10
    ) -> List[Dict[str, Any]]:
        rows = self.registry.fetch_ai_bundle_summaries()
        row = next((r for r in rows if r["bundle_id"] == bundle_id), None)
        if row is None:
            raise ValueError(f"Retrieval docs not found for bundle_id={bundle_id}")

        docs = load_json(row["retrieval_path"])
        q = query_text.lower().strip()

        scored = []
        for doc in docs:
            text = (doc.get("text") or "").lower()
            score = 0

            for token in q.split():
                if token and token in text:
                    score += 1

            if score > 0:
                scored.append((score, doc))

        scored.sort(key=lambda x: (-x[0], x[1].get("doc_id", "")))
        result = [doc for _, doc in scored[:max_results]]

        self.registry.insert_agent_query_audit({
            "query_type": "search_retrieval_docs",
            "query_text": query_text,
            "bundle_id": bundle_id,
            "filters_json": json.dumps({"max_results": max_results}),
            "result_count": len(result),
            "query_timestamp": utc_now_iso()
        })
        return result

    def fetch_detailed_events(
        self,
        bundle_id: str,
        event_type: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        keyword: Optional[str] = None,
        max_results: int = 50
    ) -> List[Dict[str, Any]]:
        bundle_rows = self.registry.fetch_ai_handoff_bundles()
        bundle_row = next((r for r in bundle_rows if r["bundle_id"] == bundle_id), None)
        if bundle_row is None:
            raise ValueError(f"Bundle not found for bundle_id={bundle_id}")

        parse_group = bundle_row["parse_group"]
        events = self.registry.fetch_bundle_events(parse_group=parse_group, limit=100000)

        filtered = []
        keyword_l = keyword.lower() if keyword else None

        for e in events:
            if event_type and e["event_type"] != event_type:
                continue
            if src_ip and e["src_ip"] != src_ip:
                continue
            if dst_ip and e["dst_ip"] != dst_ip:
                continue
            if keyword_l:
                hay = " ".join([
                    str(e["summary"] or ""),
                    str(e["raw_json"] or ""),
                    str(e["app_proto"] or ""),
                    str(e["event_type"] or "")
                ]).lower()
                if keyword_l not in hay:
                    continue

            filtered.append({
                "event_id": e["event_id"],
                "pcap_id": e["pcap_id"],
                "chunk_id": e["chunk_id"],
                "task_id": e["task_id"],
                "event_type": e["event_type"],
                "event_timestamp": e["event_timestamp"],
                "src_ip": e["src_ip"],
                "dst_ip": e["dst_ip"],
                "src_port": e["src_port"],
                "dst_port": e["dst_port"],
                "network_proto": e["network_proto"],
                "app_proto": e["app_proto"],
                "summary": e["summary"],
                "raw_json": json.loads(e["raw_json"]) if e["raw_json"] else None,
            })

            if len(filtered) >= max_results:
                break

        self.registry.insert_agent_query_audit({
            "query_type": "fetch_detailed_events",
            "query_text": keyword or "",
            "bundle_id": bundle_id,
            "filters_json": json.dumps({
                "event_type": event_type,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "keyword": keyword,
                "max_results": max_results
            }),
            "result_count": len(filtered),
            "query_timestamp": utc_now_iso()
        })
        return filtered

    def fetch_pcap_context(self, bundle_id: str) -> List[Dict[str, Any]]:
        bundle_rows = self.registry.fetch_ai_handoff_bundles()
        bundle_row = next((r for r in bundle_rows if r["bundle_id"] == bundle_id), None)
        if bundle_row is None:
            raise ValueError(f"Bundle not found for bundle_id={bundle_id}")

        parse_group = bundle_row["parse_group"]
        pcaps = self.registry.fetch_bundle_pcaps(parse_group)

        result = [
            {
                "pcap_id": r["pcap_id"],
                "filename": r["filename"],
                "full_path": r["full_path"],
                "sha256": r["sha256"],
                "capture_first_packet_time": r["capture_first_packet_time"],
                "capture_last_packet_time": r["capture_last_packet_time"],
                "capture_duration_seconds": r["capture_duration_seconds"],
                "capture_packet_count": r["capture_packet_count"],
                "overlap_class": r["overlap_class"],
                "processing_priority": r["processing_priority"],
            }
            for r in pcaps
        ]

        self.registry.insert_agent_query_audit({
            "query_type": "fetch_pcap_context",
            "query_text": "",
            "bundle_id": bundle_id,
            "filters_json": "{}",
            "result_count": len(result),
            "query_timestamp": utc_now_iso()
        })
        return result
    
    def load_case_bundle(self, bundle_id: str, max_events: int = 50000) -> Dict[str, Any]:
        """
        Convenience method for the autonomous forensic agent.
        Loads the minimum complete evidence package needed for investigation.
        """
        bundle_rows = self.registry.fetch_ai_handoff_bundles()
        bundle_row = next((r for r in bundle_rows if r["bundle_id"] == bundle_id), None)
        if bundle_row is None:
            raise ValueError(f"Bundle not found for bundle_id={bundle_id}")

        parse_group = bundle_row["parse_group"]

        summary_rows = self.registry.fetch_ai_bundle_summaries()
        summary_row = next((r for r in summary_rows if r["bundle_id"] == bundle_id), None)

        summary_path = summary_row["summary_path"] if summary_row and summary_row["summary_path"] else None
        retrieval_path = summary_row["retrieval_path"] if summary_row and summary_row["retrieval_path"] else None

        summary = load_json(summary_path) if summary_path else {}
        retrieval_docs = load_json(retrieval_path) if retrieval_path else []
        events = self.registry.fetch_bundle_events(parse_group=parse_group, limit=max_events)
        pcaps = self.registry.fetch_bundle_pcaps(parse_group)

        normalized_events = []
        for e in events:
            normalized_events.append({
                "event_id": e["event_id"],
                "pcap_id": e["pcap_id"],
                "chunk_id": e["chunk_id"],
                "task_id": e["task_id"],
                "event_type": e["event_type"],
                "event_timestamp": e["event_timestamp"],
                "src_ip": e["src_ip"],
                "dst_ip": e["dst_ip"],
                "src_port": e["src_port"],
                "dst_port": e["dst_port"],
                "network_proto": e["network_proto"],
                "app_proto": e["app_proto"],
                "summary": e["summary"],
                "raw_json": json.loads(e["raw_json"]) if e["raw_json"] else None,
            })

        pcap_context = [
            {
                "pcap_id": r["pcap_id"],
                "filename": r["filename"],
                "full_path": r["full_path"],
                "sha256": r["sha256"],
                "capture_first_packet_time": r["capture_first_packet_time"],
                "capture_last_packet_time": r["capture_last_packet_time"],
                "capture_duration_seconds": r["capture_duration_seconds"],
                "capture_packet_count": r["capture_packet_count"],
                "overlap_class": r["overlap_class"],
                "processing_priority": r["processing_priority"],
            }
            for r in pcaps
        ]

        result = {
            "bundle_id": bundle_id,
            "parse_group": parse_group,
            "summary": summary,
            "retrieval_docs": retrieval_docs,
            "events": normalized_events,
            "pcaps": pcap_context,
        }

        self.registry.insert_agent_query_audit({
            "query_type": "load_case_bundle",
            "query_text": "",
            "bundle_id": bundle_id,
            "filters_json": json.dumps({"max_events": max_events}),
            "result_count": len(normalized_events),
            "query_timestamp": utc_now_iso()
        })
        return result