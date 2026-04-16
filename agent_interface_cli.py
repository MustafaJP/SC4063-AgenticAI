import argparse
import json
from pathlib import Path

from agent_interface import AgentInterface
from agent.service import ForensicInvestigationService
from agent.agentic_service import AgenticForensicService
from agent.config import AgentConfig
from agent.reporter import write_investigation_reports
from agent.campaign import CampaignInvestigationService
from agent.campaign_reporter import write_campaign_reports


def pretty_print(data):
    print(json.dumps(data, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description="Agent Interface CLI")
    parser.add_argument("--db-path", default="evidence_registry.db")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-bundles")

    p_summary = subparsers.add_parser("get-summary")
    p_summary.add_argument("--bundle-id", required=True)

    p_search = subparsers.add_parser("search")
    p_search.add_argument("--bundle-id", required=True)
    p_search.add_argument("--query", required=True)
    p_search.add_argument("--max-results", type=int, default=10)

    p_events = subparsers.add_parser("get-events")
    p_events.add_argument("--bundle-id", required=True)
    p_events.add_argument("--event-type", default=None)
    p_events.add_argument("--src-ip", default=None)
    p_events.add_argument("--dst-ip", default=None)
    p_events.add_argument("--keyword", default=None)
    p_events.add_argument("--max-results", type=int, default=50000)

    p_pcaps = subparsers.add_parser("get-pcaps")
    p_pcaps.add_argument("--bundle-id", required=True)

    p_investigate = subparsers.add_parser("investigate")
    p_investigate.add_argument("--bundle-id", required=True)
    p_investigate.add_argument("--outdir", default="agent_outputs")
    p_investigate.add_argument("--max-events", type=int, default=50000)

    p_investigate_all = subparsers.add_parser("investigate-all")
    p_investigate_all.add_argument("--outdir", default="agent_outputs")
    p_investigate_all.add_argument("--max-events", type=int, default=50000)

    p_campaign = subparsers.add_parser("campaign-investigate")
    p_campaign.add_argument("--outdir", default="agent_outputs")
    p_campaign.add_argument("--max-events", type=int, default=50000)

    # Agentic investigation commands
    p_agentic = subparsers.add_parser("agentic-investigate")
    p_agentic.add_argument("--bundle-id", required=True)
    p_agentic.add_argument("--outdir", default="agent_outputs")
    p_agentic.add_argument("--max-events", type=int, default=50000)
    p_agentic.add_argument("--ollama-model", default="llama3.1")
    p_agentic.add_argument("--ollama-url", default="http://localhost:11434")
    p_agentic.add_argument("--max-iterations", type=int, default=8)

    p_agentic_all = subparsers.add_parser("agentic-investigate-all")
    p_agentic_all.add_argument("--outdir", default="agent_outputs")
    p_agentic_all.add_argument("--max-events", type=int, default=50000)
    p_agentic_all.add_argument("--ollama-model", default="llama3.1")
    p_agentic_all.add_argument("--ollama-url", default="http://localhost:11434")
    p_agentic_all.add_argument("--max-iterations", type=int, default=8)

    args = parser.parse_args()
    api = AgentInterface(db_path=args.db_path)

    try:
        if args.command == "list-bundles":
            pretty_print(api.list_bundles())

        elif args.command == "get-summary":
            pretty_print(api.get_bundle_summary(args.bundle_id))

        elif args.command == "search":
            pretty_print(
                api.search_retrieval_docs(
                    bundle_id=args.bundle_id,
                    query_text=args.query,
                    max_results=args.max_results
                )
            )

        elif args.command == "get-events":
            pretty_print(
                api.fetch_detailed_events(
                    bundle_id=args.bundle_id,
                    event_type=args.event_type,
                    src_ip=args.src_ip,
                    dst_ip=args.dst_ip,
                    keyword=args.keyword,
                    max_results=args.max_results
                )
            )

        elif args.command == "get-pcaps":
            pretty_print(api.fetch_pcap_context(args.bundle_id))

        elif args.command == "investigate":
            case_data = api.load_case_bundle(
                bundle_id=args.bundle_id,
                max_events=args.max_events
            )
            service = ForensicInvestigationService()
            result = service.run(case_data)

            outdir = Path(args.outdir) / args.bundle_id
            write_investigation_reports(result, outdir)

            pretty_print({
                "status": "ok",
                "bundle_id": args.bundle_id,
                "outdir": str(outdir),
                "finding_count": len(result.findings),
                "hypothesis_count": len(result.hypotheses),
            })

        elif args.command == "investigate-all":
            bundles = api.list_bundles()
            service = ForensicInvestigationService()
            results = []

            for row in bundles:
                bundle_id = row["bundle_id"]
                case_data = api.load_case_bundle(
                    bundle_id=bundle_id,
                    max_events=args.max_events
                )
                result = service.run(case_data)
                outdir = Path(args.outdir) / bundle_id
                write_investigation_reports(result, outdir)

                results.append({
                    "bundle_id": bundle_id,
                    "outdir": str(outdir),
                    "finding_count": len(result.findings),
                    "hypothesis_count": len(result.hypotheses),
                })

            pretty_print({
                "status": "ok",
                "bundle_count": len(results),
                "results": results,
            })

        elif args.command == "campaign-investigate":
            bundles = api.list_bundles()
            all_case_data = []

            for row in bundles:
                bundle_id = row["bundle_id"]
                case_data = api.load_case_bundle(
                    bundle_id=bundle_id,
                    max_events=args.max_events
                )
                all_case_data.append(case_data)

            service = CampaignInvestigationService()
            result = service.run(all_case_data)

            outdir = Path(args.outdir) / "campaign"
            write_campaign_reports(result, outdir)

            pretty_print({
                "status": "ok",
                "bundle_count": len(all_case_data),
                "campaign_finding_count": len(result.campaign_findings),
                "outdir": str(outdir),
            })

        elif args.command == "agentic-investigate":
            config = AgentConfig(
                ollama_model=args.ollama_model,
                ollama_url=args.ollama_url,
                agentic_max_iterations=args.max_iterations,
                agentic_enabled=True,
            )
            case_data = api.load_case_bundle(
                bundle_id=args.bundle_id,
                max_events=args.max_events,
            )
            service = AgenticForensicService(config=config)
            result = service.run(case_data)

            outdir = Path(args.outdir) / args.bundle_id
            write_investigation_reports(result, outdir)

            pretty_print({
                "status": "ok",
                "bundle_id": args.bundle_id,
                "outdir": str(outdir),
                "finding_count": len(result.findings),
                "hypothesis_count": len(result.hypotheses),
                "agentic_mode": result.metrics.get("agentic_mode", False),
                "tools_invoked": result.metrics.get("tools_invoked", []),
                "llm_rounds": result.metrics.get("llm_rounds", 0),
            })

        elif args.command == "agentic-investigate-all":
            config = AgentConfig(
                ollama_model=args.ollama_model,
                ollama_url=args.ollama_url,
                agentic_max_iterations=args.max_iterations,
                agentic_enabled=True,
            )
            bundles = api.list_bundles()
            service = AgenticForensicService(config=config)
            results = []

            for row in bundles:
                bundle_id = row["bundle_id"]
                case_data = api.load_case_bundle(
                    bundle_id=bundle_id,
                    max_events=args.max_events,
                )
                result = service.run(case_data)
                outdir = Path(args.outdir) / bundle_id
                write_investigation_reports(result, outdir)

                results.append({
                    "bundle_id": bundle_id,
                    "outdir": str(outdir),
                    "finding_count": len(result.findings),
                    "hypothesis_count": len(result.hypotheses),
                    "agentic_mode": result.metrics.get("agentic_mode", False),
                    "tools_invoked": result.metrics.get("tools_invoked", []),
                    "llm_rounds": result.metrics.get("llm_rounds", 0),
                })

            pretty_print({
                "status": "ok",
                "bundle_count": len(results),
                "results": results,
            })

    finally:
        api.close()


if __name__ == "__main__":
    main()