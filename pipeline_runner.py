import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def run_command(cmd, phase_name):
    print(f"\n========== RUNNING: {phase_name} ==========")
    print("Command:", " ".join(cmd))

    started = time.perf_counter()
    started_at = utc_now_iso()

    result = subprocess.run(cmd)

    finished = time.perf_counter()
    finished_at = utc_now_iso()
    elapsed_seconds = round(finished - started, 3)

    if result.returncode != 0:
        print(f"\n❌ FAILED at {phase_name}")
        return {
            "phase_name": phase_name,
            "command": cmd,
            "started_at": started_at,
            "finished_at": finished_at,
            "elapsed_seconds": elapsed_seconds,
            "status": "FAILED",
            "return_code": result.returncode,
        }

    print(f"✅ COMPLETED: {phase_name} | elapsed={elapsed_seconds}s")
    return {
        "phase_name": phase_name,
        "command": cmd,
        "started_at": started_at,
        "finished_at": finished_at,
        "elapsed_seconds": elapsed_seconds,
        "status": "SUCCESS",
        "return_code": 0,
    }


def estimate_pipeline_cost(total_runtime_seconds: float) -> dict:
    cpu_hour_rate = 0.05
    estimated_cpu_cost = round((total_runtime_seconds / 3600.0) * cpu_hour_rate, 4)

    return {
        "model": "simple_local_cpu_estimate",
        "cpu_hour_rate": cpu_hour_rate,
        "estimated_cpu_cost": estimated_cpu_cost,
    }


def build_phase_plan(args):
    db = args.db_path
    phases = []

    if 1 >= args.start_phase and 1 <= args.end_phase:
        phases.append((
            "Phase 1: File Ingestion",
            [
                "python3", "injestion/discover_pcaps.py",
                "--input-dir", args.input_dir,
                "--db-path", db,
            ],
        ))

    if 2 >= args.start_phase and 2 <= args.end_phase:
        phases.append((
            "Phase 2: Metadata Enrichment",
            [
                "python3", "injestion/extract_metadata.py",
                "--db-path", db,
            ],
        ))

    if 3 >= args.start_phase and 3 <= args.end_phase:
        cmd = [
            "python3", "injestion/build_processing_plan.py",
            "--db-path", db,
        ]
        if args.clear:
            cmd.append("--clear-existing")
        phases.append(("Phase 3: Processing Plan", cmd))

    if 4 >= args.start_phase and 4 <= args.end_phase:
        cmd = [
            "python3", "injestion/build_extraction_plan.py",
            "--db-path", db,
        ]
        if args.clear:
            cmd.append("--clear-existing")
        phases.append(("Phase 4: Extraction Plan", cmd))

    if 5 >= args.start_phase and 5 <= args.end_phase:
        cmd = [
            "python3", "injestion/extraction_executor.py",
            "--db-path", db,
        ]

        if args.step5_limit is not None:
            cmd += ["--limit", str(args.step5_limit)]

        if args.step5_task_types:
            cmd += ["--task-types", *args.step5_task_types]

        if args.step5_workers > 1:
            cmd += ["--workers", str(args.step5_workers)]

        phases.append(("Phase 5: Evidence Extraction", cmd))

    if 6 >= args.start_phase and 6 <= args.end_phase:
        cmd = [
            "python3", "injestion/build_ai_handoff.py",
            "--db-path", db,
            "--output-dir", args.bundle_dir,
        ]
        if args.clear:
            cmd.append("--clear-existing")
        phases.append(("Phase 6: Bundle Construction", cmd))

    if 7 >= args.start_phase and 7 <= args.end_phase:
        cmd = [
            "python3", "injestion/build_preai_summaries.py",
            "--db-path", db,
            "--summary-dir", args.summary_dir,
            "--retrieval-dir", args.retrieval_dir,
        ]
        if args.clear:
            cmd.append("--clear-existing")
        phases.append(("Phase 7: Summary Construction", cmd))

    if 8 >= args.start_phase and 8 <= args.end_phase:
        phases.append((
            "Phase 8: Interface Validation",
            [
                "python3", "agent_interface_cli.py",
                "--db-path", db,
                "list-bundles",
            ],
        ))

    if 9 >= args.start_phase and 9 <= args.end_phase:
        if args.agentic:
            cmd = [
                "python3", "agent_interface_cli.py",
                "--db-path", db,
                "agentic-investigate-all",
                "--outdir", args.agent_outdir,
                "--max-events", str(args.agent_max_events),
            ]
            if args.ollama_model:
                cmd += ["--ollama-model", args.ollama_model]
            if args.ollama_url:
                cmd += ["--ollama-url", args.ollama_url]
            if args.agentic_max_iterations:
                cmd += ["--max-iterations", str(args.agentic_max_iterations)]
            phases.append(("Phase 9: Agentic Investigation", cmd))
        else:
            phases.append((
                "Phase 9: Agent Investigation",
                [
                    "python3", "agent_interface_cli.py",
                    "--db-path", db,
                    "investigate-all",
                    "--outdir", args.agent_outdir,
                    "--max-events", str(args.agent_max_events),
                ],
            ))

    if 10 >= args.start_phase and 10 <= args.end_phase:
        phases.append((
            "Phase 10: Campaign Investigation",
            [
                "python3", "agent_interface_cli.py",
                "--db-path", db,
                "campaign-investigate",
                "--outdir", args.agent_outdir,
                "--max-events", str(args.agent_max_events),
            ],
        ))

    if 11 >= args.start_phase and 11 <= args.end_phase:
        cmd = [
            "python3", "master_report_synthesizer.py",
            "--agent-outdir", args.agent_outdir,
            "--master-subdir", args.master_subdir,
        ]

        if args.master_use_llm:
            cmd.append("--use-llm")

        if args.master_ollama_model:
            cmd += ["--ollama-model", args.master_ollama_model]

        phases.append(("Phase 11: Master Findings Synthesis", cmd))

    return phases


def main():
    parser = argparse.ArgumentParser(description="End-to-End Network Forensics Runner")

    parser.add_argument("--db-path", default="evidence_registry.db")
    parser.add_argument("--input-dir", default="input_pcaps")
    parser.add_argument("--bundle-dir", default="ai_handoff_bundles")
    parser.add_argument("--summary-dir", default="preai_summaries")
    parser.add_argument("--retrieval-dir", default="preai_retrieval")
    parser.add_argument("--metrics-out", default="pipeline_run_metrics.json")
    parser.add_argument("--agent-outdir", default="agent_outputs")
    parser.add_argument("--agent-max-events", type=int, default=50000)

    parser.add_argument("--master-subdir", default="master")
    parser.add_argument("--master-use-llm", action="store_true")
    parser.add_argument("--master-ollama-model", default="")

    # Agentic investigation options
    parser.add_argument("--agentic", action="store_true",
                        help="Use LLM-driven agentic investigation instead of rule-based pipeline")
    parser.add_argument("--ollama-model", default="llama3.1",
                        help="Ollama model for agentic investigation")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="Ollama server URL")
    parser.add_argument("--agentic-max-iterations", type=int, default=8,
                        help="Maximum LLM reasoning iterations per bundle")

    parser.add_argument(
        "--step5-limit",
        type=int,
        default=None,
        help="Optional maximum number of Phase 5 extraction tasks to execute. If omitted, runs the full planned set."
    )

    parser.add_argument(
        "--step5-task-types",
        nargs="+",
        choices=["flow", "dns", "http", "tls", "ioc", "timeline"],
        help="Optional Phase 5 task-type filter, e.g. --step5-task-types http tls ioc"
    )

    parser.add_argument(
        "--step5-workers",
        type=int,
        default=1,
        help="Number of parallel workers for Phase 5 extraction. Default 1 (sequential)."
    )

    parser.add_argument(
        "--start-phase",
        type=int,
        default=1,
        help="Start phase number (1-11)."
    )
    parser.add_argument(
        "--end-phase",
        type=int,
        default=11,
        help="End phase number (1-11)."
    )

    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear intermediate tables where applicable."
    )

    args = parser.parse_args()

    phases = build_phase_plan(args)

    pipeline_started = time.perf_counter()
    pipeline_started_at = utc_now_iso()

    phase_results = []
    failed = False

    for phase_name, cmd in phases:
        result = run_command(cmd, phase_name)
        phase_results.append(result)

        if result["status"] != "SUCCESS":
            failed = True
            break

    pipeline_finished = time.perf_counter()
    pipeline_finished_at = utc_now_iso()
    total_elapsed = round(pipeline_finished - pipeline_started, 3)

    metrics = {
        "started_at": pipeline_started_at,
        "finished_at": pipeline_finished_at,
        "total_elapsed_seconds": total_elapsed,
        "status": "FAILED" if failed else "SUCCESS",
        "phases": phase_results,
        "cost_estimate": estimate_pipeline_cost(total_elapsed),
    }

    metrics_path = Path(args.metrics_out).resolve()
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"\nRun metrics written to: {metrics_path}")

    if failed:
        print("\n❌ RUN FAILED")
        sys.exit(1)

    print("\n🎉 RUN COMPLETED SUCCESSFULLY")


if __name__ == "__main__":
    main()