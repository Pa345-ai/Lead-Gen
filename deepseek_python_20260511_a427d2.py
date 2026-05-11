# main.py
"""
SecureGraph — Enterprise-Grade Autonomous Vulnerability Hunter
==============================================================

CLI entry point. Wires the full pipeline:
  Static Analysis → Graph → Hypothesis Engine → Executor → Report

Modes:
  static   — Analyze source code directory, no live target
  dynamic  — Observe live traffic through mitmproxy
  full     — Static + Dynamic + Execute (full autonomous audit)
  verify   — Execute hypotheses from a saved graph against live target

Usage:
  python main.py static --source-dir ./app --output ./output
  python main.py full --source-dir ./app --target-url http://localhost:8000 --config config/target_config.yaml
  python main.py verify --graph output/graph.json --target-url http://localhost:8000 --config config/target_config.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from core.graph import StateGraph
from core.hypothesis import HypothesisEngine
from core.executor import Executor, ExecutorConfig, VerificationResult, ImpactLevel
from core.report_generator import ReportGenerator
from core.fingerprint_db import FingerprintDB
from extractors.fastapi_extractor import FastAPIExtractor


# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SecureGraph — Enterprise Autonomous Vulnerability Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")

    # Static mode
    static_parser = subparsers.add_parser("static", help="Static source analysis only")
    static_parser.add_argument("--source-dir", required=True, help="Directory containing Python source")
    static_parser.add_argument("--output", default="./output", help="Output directory")
    static_parser.add_argument("--framework", default="fastapi", choices=["fastapi"], help="Web framework")

    # Full mode
    full_parser = subparsers.add_parser("full", help="Full autonomous audit (static + dynamic + execute)")
    full_parser.add_argument("--source-dir", required=True, help="Directory containing source code")
    full_parser.add_argument("--target-url", required=True, help="Live target base URL")
    full_parser.add_argument("--config", required=True, help="Target config YAML file")
    full_parser.add_argument("--output", default="./output", help="Output directory")
    full_parser.add_argument("--dry-run", action="store_true", help="Skip execution, only hypotheses")

    # Verify mode
    verify_parser = subparsers.add_parser("verify", help="Execute hypotheses from saved graph")
    verify_parser.add_argument("--graph", required=True, help="Saved graph JSON file")
    verify_parser.add_argument("--target-url", required=True, help="Live target base URL")
    verify_parser.add_argument("--config", required=True, help="Target config YAML file")
    verify_parser.add_argument("--output", default="./output", help="Output directory")

    return parser.parse_args()


# ─── Graph building ──────────────────────────────────────────────────────────

def build_graph_from_source(source_dir: str, framework: str = "fastapi") -> StateGraph:
    """Walk source directory and extract all routes, models, and auth patterns."""
    graph = StateGraph()
    source_path = Path(source_dir)
    if not source_path.exists():
        print(f"[!] Source directory not found: {source_dir}")
        return graph

    py_files = list(source_path.rglob("*.py"))
    print(f"[*] Found {len(py_files)} Python files in {source_dir}")

    if framework == "fastapi":
        extractor = FastAPIExtractor(graph)
        model_files = []
        route_files = []

        # Heuristic: files with 'model' or 'schema' in name/path are models
        for f in py_files:
            f_str = str(f)
            if any(k in f_str.lower() for k in ["model", "schema", "pydantic"]):
                model_files.append(f)
            else:
                route_files.append(f)

        # Process models first
        for f in model_files:
            try:
                extractor.process_file(str(f))
            except Exception as e:
                print(f"  [!] Failed to parse {f}: {e}")

        # Then routes
        for f in route_files:
            try:
                extractor.process_file(str(f))
            except Exception as e:
                print(f"  [!] Failed to parse {f}: {e}")

        extractor.enrich_path_params()

    return graph


def load_graph_from_file(path: str) -> StateGraph:
    """Reconstruct a StateGraph from saved JSON."""
    graph = StateGraph()
    with open(path) as f:
        data = json.load(f)
    # Reconstruct nodes
    from core.graph import (
        EndpointNode, ParameterNode, ModelNode, ModelFieldNode,
        PermissionNode, ExternalCallNode, Edge, AuthContext,
        NodeType, EdgeType, HTTPMethod, ParamLocation,
    )
    type_map = {
        "Endpoint": EndpointNode,
        "Parameter": ParameterNode,
        "DataModel": ModelNode,
        "ModelField": ModelFieldNode,
        "Permission": PermissionNode,
        "ExternalCall": ExternalCallNode,
    }
    for nid, ndata in data.get("nodes", {}).items():
        ntype = ndata.get("type")
        cls = type_map.get(ntype)
        if cls:
            node = cls(
                id=ndata["id"],
                label=ndata.get("label", ""),
                file=ndata.get("file", ""),
                line=ndata.get("line", 0),
                metadata=ndata.get("metadata", {}),
            )
            # Set subclass-specific fields
            if isinstance(node, EndpointNode):
                node.method = HTTPMethod(ndata.get("method", "GET"))
                node.path = ndata.get("path", "")
                node.function_name = ndata.get("function_name", "")
                node.auth_required = ndata.get("auth_required", False)
                node.auth_contexts = [
                    AuthContext(**ac) for ac in ndata.get("auth_contexts", [])
                ]
            elif isinstance(node, ParameterNode):
                node.location = ParamLocation(ndata.get("location", "query"))
                node.python_type = ndata.get("python_type", "Any")
                node.required = ndata.get("required", True)
                node.user_controlled = ndata.get("user_controlled", True)
            elif isinstance(node, ModelNode):
                node.fields = ndata.get("fields", [])
                node.ownership_fields = ndata.get("ownership_fields", [])
            elif isinstance(node, ModelFieldNode):
                node.field_type = ndata.get("field_type", "Any")
                node.parent_model = ndata.get("parent_model", "")
                node.is_ownership_marker = ndata.get("is_ownership_marker", False)
            elif isinstance(node, PermissionNode):
                node.dependency_fn = ndata.get("dependency_fn", "")
                node.inferred_role = ndata.get("inferred_role", "user")
            elif isinstance(node, ExternalCallNode):
                node.call_type = ndata.get("call_type", "db")
                node.query_fragment = ndata.get("query_fragment", "")
            graph.add_node(node)

    for eid, edata in data.get("edges", {}).items():
        edge = Edge(
            src=edata["src"],
            dst=edata["dst"],
            type=EdgeType(edata["type"]),
            auth_contexts=[AuthContext(**ac) for ac in edata.get("auth_contexts", [])],
            metadata=edata.get("metadata", {}),
        )
        graph.add_edge(edge)

    return graph


def load_config(config_path: str) -> dict:
    """Load YAML configuration."""
    with open(config_path) as f:
        return yaml.safe_load(f)


def build_executor_config(config: dict) -> ExecutorConfig:
    """Build ExecutorConfig from YAML dict."""
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


# ─── Pipeline ────────────────────────────────────────────────────────────────

async def run_hypothesis_engine(graph: StateGraph, fingerprint_db: Optional[FingerprintDB] = None) -> list:
    """Run hypothesis generation with optional fingerprint matching."""
    engine = HypothesisEngine(graph)
    hypotheses = engine.run()

    # Check fingerprint database for instant hits
    if fingerprint_db:
        instant_hits = fingerprint_db.match_fingerprints(graph)
        for hit in instant_hits:
            print(f"  [fingerprint] Instant match: {hit.get('vuln_class')} on {hit.get('endpoint_id')}")
        # Instant hits don't need rule engine — they're already validated patterns
        # In a full implementation, these would be appended to hypotheses

    print(f"[*] Generated {len(hypotheses)} hypotheses")
    return hypotheses


async def run_executor(
    hypotheses: list,
    graph: StateGraph,
    executor_config: ExecutorConfig,
    fingerprint_db: Optional[FingerprintDB] = None,
) -> list[VerificationResult]:
    """Execute hypotheses against live target."""
    results = []
    async with Executor(executor_config, graph) as executor:
        for i, hyp in enumerate(hypotheses):
            print(f"  [{i+1}/{len(hypotheses)}] Testing {hyp.vuln_class} on {hyp.endpoint_id}...")
            result = await executor.validate_hypothesis(hyp)
            results.append(result)
            status_icon = "✓" if result.status.value == "verified" else "✗" if result.status.value == "disproved" else "?"
            print(f"       {status_icon} {result.status.value} — {len(result.evidence)} evidence items")

            # Feed confirmed findings into fingerprint DB
            if fingerprint_db and result.status.value == "verified":
                fingerprint_db.store_fingerprint(result, {
                    "vuln_class": hyp.vuln_class,
                    "chain_node_types": [
                        graph.get_node(nid).type.value if graph.get_node(nid) else "unknown"
                        for nid in hyp.chain
                    ],
                    "endpoint_path": graph.get_node(hyp.endpoint_id).path if graph.get_node(hyp.endpoint_id) else "",
                })

    verified = [r for r in results if r.status.value == "verified"]
    disproved = [r for r in results if r.status.value == "disproved"]
    inconclusive = [r for r in results if r.status.value == "inconclusive"]
    print(f"\n[*] Execution complete: {len(verified)} verified, {len(disproved)} disproved, {len(inconclusive)} inconclusive")
    return results


# ─── Main entry points ──────────────────────────────────────────────────────

async def mode_static(args):
    """Static analysis only."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    graph = build_graph_from_source(args.source_dir, args.framework)
    summary = graph.summary()
    print(f"\n[*] Graph built: {summary['total_nodes']} nodes, {summary['total_edges']} edges")

    # Save graph
    graph.save(str(output_dir / "graph.json"))

    # Run hypothesis engine
    hypotheses = await run_hypothesis_engine(graph)
    hyp_out = output_dir / "hypotheses.json"
    with open(hyp_out, "w") as f:
        json.dump([h.to_dict() for h in hypotheses], f, indent=2)
    print(f"[*] Saved {len(hypotheses)} hypotheses → {hyp_out}")

    # Generate report
    report_gen = ReportGenerator(output_dir=str(output_dir))
    report_gen.generate_markdown_summary(hypotheses, graph, args.source_dir)
    print(f"[*] Report saved → {output_dir}")


async def mode_full(args):
    """Full autonomous audit pipeline."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load config
    config = load_config(args.config)
    executor_config = build_executor_config(config)
    fingerprint_db = FingerprintDB(db_path=str(output_dir / "fingerprints.db"))

    # Build graph from source
    print("[1/5] Building program state graph from source...")
    graph = build_graph_from_source(args.source_dir)
    summary = graph.summary()
    print(f"      {summary['total_nodes']} nodes, {summary['total_edges']} edges")
    graph.save(str(output_dir / "graph.json"))

    # Run hypothesis engine
    print("\n[2/5] Generating vulnerability hypotheses...")
    hypotheses = await run_hypothesis_engine(graph, fingerprint_db)
    with open(output_dir / "hypotheses.json", "w") as f:
        json.dump([h.to_dict() for h in hypotheses], f, indent=2)

    if args.dry_run:
        print("\n[*] Dry run — skipping execution. Hypotheses saved to output/")
        report_gen = ReportGenerator(output_dir=str(output_dir))
        report_gen.generate_markdown_summary(hypotheses, graph, args.source_dir)
        return

    # Execute
    print("\n[3/5] Executing hypotheses against live target...")
    results = await run_executor(hypotheses, graph, executor_config, fingerprint_db)

    # Save results
    with open(output_dir / "verification_results.json", "w") as f:
        json.dump([
            {
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
            }
            for r in results
        ], f, indent=2)

    # Generate reports
    print("\n[4/5] Generating reports...")
    report_gen = ReportGenerator(output_dir=str(output_dir))
    verified = [r for r in results if r.status.value == "verified"]
    report_gen.generate_full_report(verified, results, graph, config.get("target", {}).get("name", "Target"))
    print(f"      Reports saved → {output_dir}")

    # Print summary
    print(f"\n[5/5] {'='*60}")
    print(f"  Audit Complete — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Target: {config.get('target', {}).get('name', 'Unknown')}")
    print(f"  Endpoints analyzed: {len(graph.endpoints())}")
    print(f"  Hypotheses generated: {len(hypotheses)}")
    print(f"  Verified vulnerabilities: {len(verified)}")
    for r in verified:
        print(f"    [{r.impact.value.upper()}] {r.vuln_class} — {r.endpoint_id}")
    print(f"  {'='*60}")


async def mode_verify(args):
    """Execute saved hypotheses against live target."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    config = load_config(args.config)
    executor_config = build_executor_config(config)

    # Load graph
    print("[*] Loading graph from file...")
    graph = load_graph_from_file(args.graph)
    print(f"    {graph.summary()['total_nodes']} nodes, {graph.summary()['total_edges']} edges")

    # Load hypotheses if available
    hyp_path = Path(args.graph).parent / "hypotheses.json"
    hypotheses_data = []
    if hyp_path.exists():
        with open(hyp_path) as f:
            hypotheses_data = json.load(f)

    from core.hypothesis import AttackHypothesis
    hypotheses = [AttackHypothesis(**h) for h in hypotheses_data]

    if not hypotheses:
        print("[!] No hypotheses found. Run 'full' mode first.")
        return

    # Execute
    print(f"\n[*] Executing {len(hypotheses)} hypotheses...")
    results = await run_executor(hypotheses, graph, executor_config)

    # Save and report
    with open(output_dir / "verification_results.json", "w") as f:
        json.dump([{
            "hypothesis_id": r.hypothesis_id,
            "vuln_class": r.vuln_class,
            "status": r.status.value,
            "impact": r.impact.value,
            "evidence": r.evidence,
        } for r in results], f, indent=2)

    verified = [r for r in results if r.status.value == "verified"]
    print(f"\n[*] {len(verified)} vulnerabilities verified")


def main():
    args = parse_args()
    if not args.mode:
        print("[!] No mode specified. Use: static, full, or verify")
        print("    python main.py --help")
        sys.exit(1)

    if args.mode == "static":
        asyncio.run(mode_static(args))
    elif args.mode == "full":
        asyncio.run(mode_full(args))
    elif args.mode == "verify":
        asyncio.run(mode_verify(args))


if __name__ == "__main__":
    main()