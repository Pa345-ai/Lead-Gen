"""
Integration test: extract graph from fixture FastAPI app → run hypothesis engine
→ verify expected vulnerability classes are found.

Run with:
    cd /home/claude/securegraph && python3 tests/test_pipeline.py
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.graph import StateGraph
from extractors.fastapi_extractor import FastAPIExtractor
from core.hypothesis import HypothesisEngine
from fixtures.sample_fastapi_app import FIXTURE_MODELS, FIXTURE_ROUTES


EXPECTED_VULN_CLASSES = {
    "IDOR",
    "MissingAuthentication",
    "AuthBypassPathAsymmetry",
    "MassAssignment",
}

ANSI_GREEN  = "\033[32m"
ANSI_RED    = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_BOLD   = "\033[1m"
ANSI_RESET  = "\033[0m"


def run() -> None:
    print(f"\n{ANSI_BOLD}═══ SecureGraph Phase 1 — Integration Test ═══{ANSI_RESET}\n")

    # ── Step 1: Build graph ───────────────────────────────────────────────────
    print(f"{ANSI_BOLD}[1/3] Building program state graph...{ANSI_RESET}")
    graph = StateGraph()
    extractor = FastAPIExtractor(graph)

    # Parse models first (so extractor knows Pydantic types for body param classification)
    extractor.process_source(FIXTURE_MODELS, label="fixture:models")
    extractor.process_source(FIXTURE_ROUTES, label="fixture:routes")
    extractor.enrich_path_params()

    summary = graph.summary()
    print(f"  Nodes: {summary['total_nodes']}")
    print(f"  Edges: {summary['total_edges']}")
    print(f"  By type: {json.dumps(summary['by_node_type'], indent=4)}\n")

    # ── Step 2: Print all endpoints ───────────────────────────────────────────
    print(f"{ANSI_BOLD}[2/3] Extracted endpoints:{ANSI_RESET}")
    endpoints = graph.endpoints()
    for ep in endpoints:
        auth_flag = f"{ANSI_GREEN}✓ auth{ANSI_RESET}" if ep.auth_required else f"{ANSI_RED}✗ NO AUTH{ANSI_RESET}"
        print(f"  {ep.method.value:<7} {ep.path:<35} {auth_flag}  fn={ep.function_name}")

    # ── Step 3: Run hypothesis engine ─────────────────────────────────────────
    print(f"\n{ANSI_BOLD}[3/3] Running hypothesis engine...{ANSI_RESET}\n")
    engine = HypothesisEngine(graph)
    hypotheses = engine.run()

    found_classes = set()
    for i, h in enumerate(hypotheses, 1):
        sev_color = {
            "Critical": ANSI_RED,
            "High": ANSI_YELLOW,
            "Medium": ANSI_YELLOW,
            "Low": ANSI_GREEN,
        }.get(h.severity_estimate, ANSI_RESET)

        print(f"  [{i}] {ANSI_BOLD}{h.vuln_class}{ANSI_RESET}")
        print(f"      Severity:   {sev_color}{h.severity_estimate}{ANSI_RESET}")
        print(f"      Confidence: {h.confidence:.0%}")
        print(f"      Endpoint:   {h.endpoint_id}")
        print(f"      Description: {h.description}")
        print(f"      Attack:     {h.attack_transform}")
        print(f"      Evidence:")
        for ev in h.evidence:
            print(f"        • {ev}")
        print()
        found_classes.add(h.vuln_class)

    # ── Assertions ────────────────────────────────────────────────────────────
    print(f"{ANSI_BOLD}═══ Test Results ═══{ANSI_RESET}\n")

    all_pass = True
    for expected in sorted(EXPECTED_VULN_CLASSES):
        if expected in found_classes:
            print(f"  {ANSI_GREEN}✓ PASS{ANSI_RESET}  {expected}")
        else:
            print(f"  {ANSI_RED}✗ FAIL{ANSI_RESET}  {expected} — NOT FOUND")
            all_pass = False

    # Check for false positives on known-safe endpoints
    safe_paths = {"/products/{product_id}", "/health"}
    for h in hypotheses:
        ep = graph.get_node(h.endpoint_id)
        if ep and hasattr(ep, "path") and ep.path in safe_paths:
            if h.confidence > 0.5:
                print(f"  {ANSI_RED}✗ FALSE POSITIVE{ANSI_RESET}  {h.vuln_class} on safe endpoint {ep.path}")
                all_pass = False

    print()
    if all_pass:
        print(f"{ANSI_GREEN}{ANSI_BOLD}All tests passed. ✓{ANSI_RESET}")
    else:
        print(f"{ANSI_RED}{ANSI_BOLD}Some tests failed. ✗{ANSI_RESET}")

    # ── Save graph ────────────────────────────────────────────────────────────
    out = Path("/home/claude/securegraph/output")
    out.mkdir(exist_ok=True)
    graph.save(str(out / "graph.json"))

    hyp_out = out / "hypotheses.json"
    with open(hyp_out, "w") as f:
        json.dump([h.to_dict() for h in hypotheses], f, indent=2)
    print(f"[graph] Saved {len(hypotheses)} hypotheses → {hyp_out}")


if __name__ == "__main__":
    run()
