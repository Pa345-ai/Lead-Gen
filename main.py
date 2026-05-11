# main.py (corrected – enterprise wiring)
#
# Changes:
# 1. Framework router now handles "django" and "express".
# 2. ChainReasoner integrated into hypothesis generation.
# 3. "dynamic" CLI mode added to launch the Omni‑Observer.

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from core.graph import StateGraph
from core.hypothesis import HypothesisEngine
from core.chain_reasoner import ChainReasoner          # ← NEW import
from core.executor import Executor, ExecutorConfig, VerificationResult, ImpactLevel
from core.report_generator import ReportGenerator
from core.fingerprint_db import FingerprintDB
from extractors.fastapi_extractor import FastAPIExtractor
from extractors.django_extractor import DjangoExtractor      # ← NEW
from extractors.express_extractor import ExpressExtractor    # ← NEW


# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SecureGraph — Enterprise Autonomous Vulnerability Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")

    # Static mode
    static_parser = subparsers.add_parser("static", help="Static source analysis only")
    static_parser.add_argument("--source-dir", required=True, help="Directory containing source code")
    static_parser.add_argument("--output", default="./output", help="Output directory")
    static_parser.add_argument("--framework", default="fastapi",
                               choices=["fastapi", "django", "express"],
                               help="Web framework")

    # Full mode
    full_parser = subparsers.add_parser("full", help="Full autonomous audit (static + dynamic + execute)")
    full_parser.add_argument("--source-dir", required=True, help="Directory containing source code")
    full_parser.add_argument("--target-url", required=True, help="Live target base URL")
    full_parser.add_argument("--config", required=True, help="Target config YAML file")
    full_parser.add_argument("--output", default="./output", help="Output directory")
    full_parser.add_argument("--framework", default="fastapi",
                             choices=["fastapi", "django", "express"],
                             help="Web framework")
    full_parser.add_argument("--dry-run", action="store_true", help="Skip execution, only hypotheses")

    # Verify mode
    verify_parser = subparsers.add_parser("verify", help="Execute hypotheses from saved graph")
    verify_parser.add_argument("--graph", required=True, help="Saved graph JSON file")
    verify_parser.add_argument("--target-url", required=True, help="Live target base URL")
    verify_parser.add_argument("--config", required=True, help="Target config YAML file")
    verify_parser.add_argument("--output", default="./output", help="Output directory")

    # Dynamic mode (NEW)
    dynamic_parser = subparsers.add_parser(
        "dynamic", help="Run the Omni‑Observer (mitmproxy) to watch live traffic"
    )
    dynamic_parser.add_argument("--target-url", required=True, help="Base URL of the target API")
    dynamic_parser.add_argument("--port", type=int, default=8080, help="Proxy listen port")
    dynamic_parser.add_argument("--save-path", default="./observer_graph.json",
                                help="Where to save the observed graph")

    return parser.parse_args()


# ─── Graph building (corrected framework router) ───────────────────────────

def build_graph_from_source(source_dir: str, framework: str = "fastapi") -> StateGraph:
    """Walk source directory and extract routes, models, and auth patterns."""
    graph = StateGraph()
    source_path = Path(source_dir)
    if not source_path.exists():
        print(f"[!] Source directory not found: {source_dir}")
        return graph

    py_files = list(source_path.rglob("*.py"))
    js_files = list(source_path.rglob("*.js")) + list(source_path.rglob("*.ts"))
    print(f"[*] Found {len(py_files)} Python files, {len(js_files)} JS/TS files in {source_dir}")

    if framework == "fastapi":
        extractor = FastAPIExtractor(graph)
        model_files = [f for f in py_files if any(k in str(f).lower() for k in ["model", "schema", "pydantic"])]
        route_files = [f for f in py_files if f not in model_files]
        for f in model_files:
            try:
                extractor.process_file(str(f))
            except Exception as e:
                print(f"  [!] Failed to parse {f}: {e}")
        for f in route_files:
            try:
                extractor.process_file(str(f))
            except Exception as e:
                print(f"  [!] Failed to parse {f}: {e}")
        extractor.enrich_path_params()

    elif framework == "django":
        extractor = DjangoExtractor(graph)
        for f in py_files:
            try:
                extractor.process_file(str(f))
            except Exception as e:
                print(f"  [!] Failed to parse {f}: {e}")
        extractor.build_endpoints()

    elif framework == "express":
        extractor = ExpressExtractor(graph)
        for f in js_files:
            try:
                extractor.process_file(str(f))
            except Exception as e:
                print(f"  [!] Failed to parse {f}: {e}")

    return graph


def load_graph_from_file(path: str) -> StateGraph:
    """Reconstruct a StateGraph from saved JSON."""
    # (unchanged – omitted for brevity, but present in original)
    pass  # full implementation in original main.py


def load_config(config_path: str) -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)


def build_executor_config(config: dict) -> ExecutorConfig:
    exec_cfg = config.get("execution", {})
    auth_cfg = config.get("auth", {})
    target_cfg = config.get("target", {})
    return ExecutorConfig(
        base_url=target_cfg.get("base_url", "http://localhost:8000"),
        seed_tokens=auth_cfg.get("seed_tokens", {}),
        allow_self_registration=auth_cfg.get("allow_self_registration", False),
        registration_endpoint=auth_cfg.get("registration_endpoint"),
        login_endpoint=auth_cfg.get("login_endpoint"),
        allow_destructive_actions=exec_cfg.get("allow_destructive_actions", False),
        max_impact=ImpactLevel(exec_cfg.get("max_impact", "medium")),
        request_timeout=exec_cfg.get("request_timeout", 30.0),
        step_delay_ms=exec_cfg.get("step_delay_ms", 750),
        enable_teardown=exec_cfg.get("enable_teardown", True),
        auth_header_name=auth_cfg.get("auth_header_name"),
    )


# ─── Pipeline (ChainReasoner integrated) ──────────────────────────────────

async def run_hypothesis_engine(graph: StateGraph,
                                fingerprint_db: Optional[FingerprintDB] = None) -> list:
    """Run hypothesis generation including multi‑hop chain analysis."""
    engine = HypothesisEngine(graph)
    hypotheses = engine.run()

    # Integrate ChainReasoner for multi‑hop IDOR detection
    chain_engine = ChainReasoner(graph)
    multi_hop_hyps = chain_engine.run_all_checks()
    hypotheses.extend(multi_hop_hyps)
    print(f"[*] ChainReasoner added {len(multi_hop_hyps)} multi‑hop hypotheses")

    if fingerprint_db:
        instant_hits = fingerprint_db.match_fingerprints(graph)
        for hit in instant_hits:
            print(f"  [fingerprint] Instant match: {hit.get('vuln_class')} on {hit.get('endpoint_id')}")

    print(f"[*] Total hypotheses generated: {len(hypotheses)}")
    return hypotheses


async def run_executor(hypotheses, graph, executor_config, fingerprint_db=None):
    # (unchanged, same as original)
    pass


# ─── Mode implementations ────────────────────────────────────────────────────

async def mode_static(args):
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    graph = build_graph_from_source(args.source_dir, args.framework)
    summary = graph.summary()
    print(f"\n[*] Graph built: {summary['total_nodes']} nodes, {summary['total_edges']} edges")
    graph.save(str(output_dir / "graph.json"))
    hypotheses = await run_hypothesis_engine(graph)
    with open(output_dir / "hypotheses.json", "w") as f:
        json.dump([h.to_dict() for h in hypotheses], f, indent=2)
    report_gen = ReportGenerator(output_dir=str(output_dir))
    report_gen.generate_markdown_summary(hypotheses, graph, args.source_dir)
    print(f"[*] Report saved → {output_dir}")


async def mode_full(args):
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    config = load_config(args.config)
    executor_config = build_executor_config(config)
    fingerprint_db = FingerprintDB(db_path=str(output_dir / "fingerprints.db"))

    print("[1/5] Building program state graph from source...")
    graph = build_graph_from_source(args.source_dir, args.framework)
    summary = graph.summary()
    print(f"      {summary['total_nodes']} nodes, {summary['total_edges']} edges")
    graph.save(str(output_dir / "graph.json"))

    print("\n[2/5] Generating vulnerability hypotheses...")
    hypotheses = await run_hypothesis_engine(graph, fingerprint_db)
    with open(output_dir / "hypotheses.json", "w") as f:
        json.dump([h.to_dict() for h in hypotheses], f, indent=2)

    if args.dry_run:
        print("\n[*] Dry run – skipping execution.")
        report_gen = ReportGenerator(output_dir=str(output_dir))
        report_gen.generate_markdown_summary(hypotheses, graph, args.source_dir)
        return

    print("\n[3/5] Executing hypotheses against live target...")
    results = await run_executor(hypotheses, graph, executor_config, fingerprint_db)
    with open(output_dir / "verification_results.json", "w") as f:
        json.dump([{
            "hypothesis_id": r.hypothesis_id,
            "vuln_class": r.vuln_class,
            "endpoint_id": r.endpoint_id,
            "status": r.status.value,
            "impact": r.impact.value,
            "evidence": r.evidence,
            "request_log": r.request_log,
            "error": r.error,
            "teardown_performed": r.teardown_performed,
            "cleanup_exceptions": r.cleanup_exceptions,
        } for r in results], f, indent=2)

    print("\n[4/5] Generating reports...")
    report_gen = ReportGenerator(output_dir=str(output_dir))
    verified = [r for r in results if r.status.value == "verified"]
    report_gen.generate_full_report(verified, results, graph,
                                   config.get("target", {}).get("name", "Target"))
    print(f"      Reports saved → {output_dir}")

    print(f"\n[5/5] {'='*60}")
    print(f"  Audit Complete — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Verified vulnerabilities: {len(verified)}")
    for r in verified:
        print(f"    [{r.impact.value.upper()}] {r.vuln_class} — {r.endpoint_id}")


async def mode_verify(args):
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    config = load_config(args.config)
    executor_config = build_executor_config(config)
    graph = load_graph_from_file(args.graph)
    print(f"[*] Graph loaded: {graph.summary()['total_nodes']} nodes")
    hyp_path = Path(args.graph).parent / "hypotheses.json"
    if not hyp_path.exists():
        print("[!] No hypotheses file found.")
        return
    with open(hyp_path) as f:
        hypotheses_data = json.load(f)
    from core.hypothesis import AttackHypothesis
    hypotheses = [AttackHypothesis(**h) for h in hypotheses_data]
    print(f"\n[*] Executing {len(hypotheses)} hypotheses...")
    results = await run_executor(hypotheses, graph, executor_config)
    with open(output_dir / "verification_results.json", "w") as f:
        json.dump([{
            "hypothesis_id": r.hypothesis_id,
            "vuln_class": r.vuln_class,
            "status": r.status.value,
            "impact": r.impact.value,
            "evidence": r.evidence,
        } for r in results], f, indent=2)
    verified = [r for r in results if r.status.value == "verified"]
    print(f"\n[*] {len(verified)} vulnerabilities verified.")


async def mode_dynamic(args):
    """Launch mitmproxy with the Omni‑Observer addon."""
    print(f"[*] Starting Dynamic Observer on port {args.port}...")
    print(f"    Target base URL: {args.target_url}")
    print(f"    Graph will be saved to: {args.save_path}")
    # Construct mitmdump command
    cmd = [
        "mitmdump",
        "-s", "extractors/dynamic_observer.py",
        "--set", f"observer_base_url={args.target_url}",
        "--set", f"observer_save_path={args.save_path}",
        "-p", str(args.port),
    ]
    print(f"    Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[*] Observer stopped.")


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    if not args.mode:
        print("[!] No mode specified. Use: static, full, dynamic, or verify")
        print("    python main.py --help")
        sys.exit(1)

    if args.mode == "static":
        asyncio.run(mode_static(args))
    elif args.mode == "full":
        asyncio.run(mode_full(args))
    elif args.mode == "verify":
        asyncio.run(mode_verify(args))
    elif args.mode == "dynamic":
        asyncio.run(mode_dynamic(args))


if __name__ == "__main__":
    main()
