# tests/test_executor.py
"""
Executor integration tests.

Requires a live FastAPI app running with the fixture vulnerabilities.
Start with:
    cd tests && python -m pytest test_executor.py -v

Or test against the fixture app:
    python tests/test_executor.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
import pytest

from core.graph import StateGraph
from core.executor import (
    Executor, ExecutorConfig, VerificationResult, VerificationStatus,
    ImpactLevel, RequestTemplate, CredentialStore,
)
from core.hypothesis import AttackHypothesis, HypothesisEngine
from extractors.fastapi_extractor import FastAPIExtractor
from fixtures.sample_fastapi_app import FIXTURE_MODELS, FIXTURE_ROUTES


# ─── Test Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def graph() -> StateGraph:
    """Build the state graph from the FastAPI fixture."""
    g = StateGraph()
    extractor = FastAPIExtractor(g)
    extractor.process_source(FIXTURE_MODELS, label="fixture:models")
    extractor.process_source(FIXTURE_ROUTES, label="fixture:routes")
    extractor.enrich_path_params()
    return g


@pytest.fixture
def hypotheses(graph) -> list[AttackHypothesis]:
    """Generate all hypotheses for the fixture app."""
    engine = HypothesisEngine(graph)
    return engine.run()


@pytest.fixture
def executor_config() -> ExecutorConfig:
    """Default executor config pointing at localhost."""
    return ExecutorConfig(
        base_url="http://localhost:8000",
        seed_tokens={
            "user": "test_user_token_placeholder",
            "admin": "test_admin_token_placeholder",
            "attacker": "test_attacker_token_placeholder",
        },
        allow_self_registration=False,
        allow_destructive_actions=False,  # safe by default
        max_impact=ImpactLevel.HIGH,
        step_delay_ms=100,
        enable_teardown=True,
        auth_header_name="Authorization",
    )


# ─── Unit Tests (no live server needed) ─────────────────────────────────────

class TestCredentialStore:
    def test_seed_tokens_populated(self):
        config = ExecutorConfig(base_url="http://test", seed_tokens={"user": "abc123"})
        store = CredentialStore(config)
        assert store.get_token("user") == "abc123"
        assert store.get_token("anonymous") is None

    def test_store_and_get_data(self):
        config = ExecutorConfig(base_url="http://test")
        store = CredentialStore(config)
        store.store("setup_1.resource_id", "42")
        assert store.get("setup_1.resource_id") == "42"
        assert store.get("nonexistent") is None

    def test_namespaced_data(self):
        config = ExecutorConfig(base_url="http://test")
        store = CredentialStore(config)
        store.store("step1.resource.id", 100)
        store.store("step2.resource.id", 200)
        assert store.get("step1.resource.id") == 100
        assert store.get("step2.resource.id") == 200


class TestRequestTemplate:
    def test_static_url(self):
        template = RequestTemplate(
            method="GET",
            url="/api/health",
        )
        assert template.resolve_url({}) == "/api/health"

    def test_dynamic_url_resolution(self):
        template = RequestTemplate(
            method="GET",
            url_template="/orders/{id}",
            url_vars={"id": "setup_1.resource_id"},
        )
        stored = {"setup_1": {"resource_id": "42"}}
        assert template.resolve_url(stored) == "/orders/42"

    def test_missing_var_leaves_placeholder(self):
        template = RequestTemplate(
            method="GET",
            url_template="/orders/{id}",
            url_vars={"id": "missing_path"},
        )
        assert template.resolve_url({}) == "/orders/{id}"


class TestSuccessOracle:
    def test_default_oracle_2xx_no_blacklist(self):
        """The default oracle should accept 200 with clean body."""
        config = ExecutorConfig(base_url="http://test")
        graph = StateGraph()
        executor = Executor(config, graph)
        step = RequestTemplate(method="GET", url="/test")
        # Mock response
        class MockResp:
            status_code = 200
            text = '{"success": true}'
        assert executor._default_success_oracle(MockResp(), step) is True

    def test_default_oracle_rejects_error_body(self):
        config = ExecutorConfig(base_url="http://test")
        graph = StateGraph()
        executor = Executor(config, graph)
        step = RequestTemplate(method="GET", url="/test")
        class MockResp:
            status_code = 200
            text = '{"error": "unauthorized"}'
        assert executor._default_success_oracle(MockResp(), step) is False

    def test_default_oracle_rejects_4xx(self):
        config = ExecutorConfig(base_url="http://test")
        graph = StateGraph()
        executor = Executor(config, graph)
        step = RequestTemplate(method="GET", url="/test")
        class MockResp:
            status_code = 401
            text = ""
        assert executor._default_success_oracle(MockResp(), step) is False

    def test_default_oracle_requires_json_paths(self):
        config = ExecutorConfig(base_url="http://test")
        graph = StateGraph()
        executor = Executor(config, graph)
        step = RequestTemplate(
            method="GET",
            url="/test",
            json_path_required=["$.id"],
        )
        class MockResp:
            status_code = 200
            text = '{"id": 42, "name": "test"}'
        assert executor._default_success_oracle(MockResp(), step) is True

        class MockRespNoId:
            status_code = 200
            text = '{"name": "test"}'
        assert executor._default_success_oracle(MockRespNoId(), step) is False


# ─── Integration Tests (requires live server) ───────────────────────────────

@pytest.mark.integration
class TestExecutorIntegration:
    """These tests require a live FastAPI server running the fixture app."""

    @pytest.mark.asyncio
    async def test_idor_hypothesis_generated(self, graph, hypotheses):
        """Verify IDOR hypothesis exists for GET /orders/{order_id}."""
        idor_hyps = [h for h in hypotheses if h.vuln_class == "IDOR"]
        assert len(idor_hyps) > 0, "Expected at least one IDOR hypothesis"
        # Check it targets the right endpoint
        order_idor = [h for h in idor_hyps if "/orders/{order_id}" in h.endpoint_id]
        assert len(order_idor) > 0, "Expected IDOR on /orders/{order_id}"

    @pytest.mark.asyncio
    async def test_missing_auth_hypothesis(self, graph, hypotheses):
        """Verify MissingAuthentication hypothesis for DELETE /orders/{order_id}."""
        missing = [h for h in hypotheses if h.vuln_class == "MissingAuthentication"]
        delete_missing = [h for h in missing if "delete" in h.endpoint_id.lower()]
        assert len(delete_missing) > 0, "Expected MissingAuth on DELETE /orders/{order_id}"

    @pytest.mark.asyncio
    async def test_mass_assignment_hypothesis(self, graph, hypotheses):
        """Verify MassAssignment hypothesis for POST /orders."""
        mass = [h for h in hypotheses if h.vuln_class == "MassAssignment"]
        assert len(mass) > 0, "Expected MassAssignment hypothesis"

    @pytest.mark.asyncio
    async def test_path_asymmetry_hypothesis(self, graph, hypotheses):
        """Verify AuthBypassPathAsymmetry for /admin/users."""
        asym = [h for h in hypotheses if h.vuln_class == "AuthBypassPathAsymmetry"]
        admin_asym = [h for h in asym if "/admin/users" in h.endpoint_id]
        assert len(admin_asym) > 0, "Expected PathAsymmetry on /admin/users"

    @pytest.mark.asyncio
    async def test_no_false_positives_on_safe_endpoints(self, graph, hypotheses):
        """Verify /health and /products have no high-confidence hypotheses."""
        safe_paths = {"/products/{product_id}", "/health"}
        for h in hypotheses:
            ep = graph.get_node(h.endpoint_id)
            if ep and hasattr(ep, "path") and ep.path in safe_paths:
                assert h.confidence <= 0.5, (
                    f"False positive: {h.vuln_class} on {ep.path} with confidence {h.confidence}"
                )


# ─── Manual test runner ─────────────────────────────────────────────────────

def run_manual_tests():
    """Run all unit tests without pytest (useful for quick validation)."""
    print("=" * 60)
    print("SecureGraph — Executor Unit Tests")
    print("=" * 60)

    # Credential store tests
    print("\n[CredentialStore]")
    TestCredentialStore().test_seed_tokens_populated()
    print("  ✓ seed_tokens_populated")
    TestCredentialStore().test_store_and_get_data()
    print("  ✓ store_and_get_data")
    TestCredentialStore().test_namespaced_data()
    print("  ✓ namespaced_data")

    # RequestTemplate tests
    print("\n[RequestTemplate]")
    TestRequestTemplate().test_static_url()
    print("  ✓ static_url")
    TestRequestTemplate().test_dynamic_url_resolution()
    print("  ✓ dynamic_url_resolution")
    TestRequestTemplate().test_missing_var_leaves_placeholder()
    print("  ✓ missing_var_leaves_placeholder")

    # SuccessOracle tests
    print("\n[SuccessOracle]")
    TestSuccessOracle().test_default_oracle_2xx_no_blacklist()
    print("  ✓ 2xx_no_blacklist")
    TestSuccessOracle().test_default_oracle_rejects_error_body()
    print("  ✓ rejects_error_body")
    TestSuccessOracle().test_default_oracle_rejects_4xx()
    print("  ✓ rejects_4xx")
    TestSuccessOracle().test_default_oracle_requires_json_paths()
    print("  ✓ requires_json_paths")

    print("\n" + "=" * 60)
    print("All unit tests passed. ✓")
    print("=" * 60)


if __name__ == "__main__":
    run_manual_tests()
