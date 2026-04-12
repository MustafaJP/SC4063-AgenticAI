import argparse
import json
from datetime import datetime
from pathlib import Path

from registry import EvidenceRegistry


def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def main(db_path: str, out_path: str):
    registry = EvidenceRegistry(db_path=db_path)

    try:
        task_runs = registry.fetch_task_runs(limit=100000)
        normalized_events = registry.fetch_normalized_events(limit=1000000)
        bundles = registry.fetch_ai_handoff_bundles()
        summaries = registry.fetch_ai_bundle_summaries()

        total_runs = len(task_runs)
        success_runs = 0
        failed_runs = 0
        total_runtime = 0.0
        total_records = 0

        task_type_stats = {}

        for row in task_runs:
            task_type = row["task_type"]
            started = parse_ts(row["run_started_at"])
            finished = parse_ts(row["run_finished_at"])

            duration = 0.0
            if started and finished:
                duration = max(0.0, (finished - started).total_seconds())

            status = row["run_status"]
            records_written = row["records_written"] or 0

            total_runtime += duration
            total_records += records_written

            if status == "SUCCESS":
                success_runs += 1
            else:
                failed_runs += 1

            if task_type not in task_type_stats:
                task_type_stats[task_type] = {
                    "runs": 0,
                    "success_runs": 0,
                    "failed_runs": 0,
                    "total_runtime_seconds": 0.0,
                    "total_records_written": 0,
                }

            task_type_stats[task_type]["runs"] += 1
            task_type_stats[task_type]["total_runtime_seconds"] += duration
            task_type_stats[task_type]["total_records_written"] += records_written

            if status == "SUCCESS":
                task_type_stats[task_type]["success_runs"] += 1
            else:
                task_type_stats[task_type]["failed_runs"] += 1

        for task_type, stats in task_type_stats.items():
            runs = stats["runs"] or 1
            records = stats["total_records_written"] or 0

            stats["total_runtime_seconds"] = round(stats["total_runtime_seconds"], 3)
            stats["avg_runtime_seconds"] = round(stats["total_runtime_seconds"] / runs, 3)
            stats["avg_records_per_run"] = round(records / runs, 3) if runs else 0.0
            stats["records_per_second"] = round(records / stats["total_runtime_seconds"], 3) if stats["total_runtime_seconds"] > 0 else 0.0

        summary = {
            "overall": {
                "task_runs": total_runs,
                "success_runs": success_runs,
                "failed_runs": failed_runs,
                "success_rate": round(success_runs / total_runs, 3) if total_runs else 0.0,
                "total_runtime_seconds": round(total_runtime, 3),
                "total_records_written": total_records,
                "records_per_second": round(total_records / total_runtime, 3) if total_runtime > 0 else 0.0,
                "normalized_event_count": len(normalized_events),
                "bundle_count": len(bundles),
                "summary_count": len(summaries),
            },
            "by_task_type": task_type_stats,
        }

        out = Path(out_path).resolve()
        out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps(summary, indent=2))
        print(f"\nSaved run metrics summary to: {out}")

    finally:
        registry.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Summarize pipeline run metrics from the registry.")
    parser.add_argument("--db-path", default="evidence_registry.db")
    parser.add_argument("--out", default="run_metrics_summary.json")
    args = parser.parse_args()

    main(db_path=args.db_path, out_path=args.out)