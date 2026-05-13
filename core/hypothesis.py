# core/hypothesis.py
"""
Vulnerability Hypothesis Engine – with false positive reduction.

Changes:
  - Public endpoint allowlist (skip MissingAuthentication on known public writes).
  - IDOR generation only if response model has ownership fields.
  - Path asymmetry only when unauthenticated method is write and authenticated methods are reads.
"""

from __future__ import annotations

import json
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Set

from core.graph import (
    StateGraph,
    EndpointNode,
    ParameterNode,
    ModelNode,
    ModelFieldNode,
    PermissionNode,
    NodeType,
    EdgeType,
    ParamLocation,
    HTTPMethod,
)


# ─── Load allowlist (public endpoints) ───────────────────────────────────────
def _load_allowlist() -> Set[str]:
    """
    Load YAML allowlist of public write endpoints that should NOT trigger
    MissingAuthentication warnings.
    """
    allow_path = Path("allowlist.yaml")
    if not allow_path.exists():
        return set()
    try:
        with open(allow_path, "r") as f:
            data = yaml.safe_load(f)
        return set(data.get("public_write_endpoints", []))
    except Exception:
        return set()


PUBLIC_WRITE_ALLOWLIST = _load_allowlist()


# ─── Hypothesis data model ────────────────────────────────────────────────────
@dataclass
class AttackHypothesis:
    vuln_class: str
    endpoint_id: str
    description: str
    chain: list[str]
    severity_estimate: str
    confidence: float
    evidence: list[str]
    attack_transform: str
    llm_score: Optional[float] = None
    llm_narrative: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "vuln_class": self.vuln_class,
            "endpoint_id": self.endpoint_id,
            "description": self.description,
            "chain": self.chain,
            "severity_estimate": self.severity_estimate,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "attack_transform": self.attack_transform,
            "llm_score": self.llm_score,
            "llm_narrative": self.llm_narrative,
        }


# ─── Rule-based candidate generators ─────────────────────────────────────────
class HypothesisEngine:
    """
    Traverses the StateGraph and produces AttackHypothesis candidates.

    Process:
      1. Graph traversal → raw candidates
      2. Rule filter    → structurally valid candidates only
      3. LLM ranking    → scored + narrated (optional, requires API key)
    """

    def __init__(self, graph: StateGraph):
        self.graph = graph
        self.hypotheses: list[AttackHypothesis] = []

    def run(self) -> list[AttackHypothesis]:
        self.hypotheses = []
        self._check_idor()
        self._check_missing_auth()
        self._check_auth_bypass_path_asymmetry()
        self._check_unauthenticated_write()
        self._check_user_controlled_id_no_ownership()
        self._check_missing_ownership_on_related_model()
        # Sort by confidence desc
        self.hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return self.hypotheses

    # ── IDOR (corrected with ownership field check) ──────────────────────────
    def _check_idor(self) -> None:
        """
        Pattern: endpoint accepts a path/query ID param + endpoint is authenticated
        + the model the ID references has an owner field
        + no ownership constraint is explicit in auth context.
        """
        for ep in self.graph.endpoints():
            if not ep.auth_required:
                continue  # IDOR requires auth (otherwise it's just unauth access)

            # Find ID-looking path/query parameters
            id_params = self._id_params_for_endpoint(ep)
            if not id_params:
                continue

            # Check if any response model has ownership fields
            has_ownership_model = False
            for edge in self.graph.outgoing(ep.id):
                if edge.type == EdgeType.RESPONSE_SHAPE:
                    model = self.graph.get_node(edge.dst)
                    if isinstance(model, ModelNode) and model.ownership_fields:
                        has_ownership_model = True
                        break

            # If the resource has no ownership fields, IDOR is impossible
            if not has_ownership_model:
                continue

            # Check auth contexts: does any have an ownership constraint?
            has_ownership_constraint = any(
                ac.has_ownership_check() for ac in ep.auth_contexts
            )

            for param in id_params:
                evidence = [
                    f"Endpoint {ep.path} accepts user-controlled ID param '{param.label}'",
                    f"Auth required: {ep.auth_required}",
                    f"Ownership constraint in auth context: {has_ownership_constraint}",
                    f"Response model has ownership fields: {has_ownership_model}",
                ]

                if has_ownership_constraint:
                    conf = 0.3
                    desc = (
                        f"Potential IDOR on {ep.method.value} {ep.path} — ownership "
                        f"constraint detected but not verified to cover all code paths."
                    )
                    severity = "Low"
                else:
                    conf = 0.82
                    desc = (
                        f"IDOR: {ep.method.value} {ep.path} accepts user-controlled "
                        f"'{param.label}' with no ownership enforcement detected, "
                        f"and the resource is user-owned."
                    )
                    severity = "High"

                h = AttackHypothesis(
                    vuln_class="IDOR",
                    endpoint_id=ep.id,
                    description=desc,
                    chain=[param.id, ep.id],
                    severity_estimate=severity,
                    confidence=conf,
                    evidence=evidence,
                    attack_transform=(
                        f"Replace '{param.label}' value with another user's resource ID. "
                        f"Observe if response returns that user's data."
                    ),
                )
                self.hypotheses.append(h)

    def _id_params_for_endpoint(self, ep: EndpointNode) -> list[ParameterNode]:
        """Return params that look like object ID selectors."""
        id_patterns = ["_id", "id", "Id", "ID", "uuid", "key", "token"]
        result = []
        for edge in self.graph.incoming(ep.id):
            if edge.type != EdgeType.PARAM_FLOWS_TO:
                continue
            node = self.graph.get_node(edge.src)
            if not isinstance(node, ParameterNode):
                continue
            if node.location not in (ParamLocation.PATH, ParamLocation.QUERY):
                continue
            if any(p in node.label for p in id_patterns):
                result.append(node)
        return result

    # ── Missing auth (with allowlist) ──────────────────────────────────────────
    def _check_missing_auth(self) -> None:
        """
        Pattern: endpoint is a write operation (POST/PUT/PATCH/DELETE)
        with no auth context at all, and is not in the public allowlist.
        """
        write_methods = {HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.PATCH, HTTPMethod.DELETE}

        for ep in self.graph.endpoints():
            if ep.method not in write_methods:
                continue
            if ep.auth_required:
                continue

            # Skip allowlisted public endpoints
            if ep.path in PUBLIC_WRITE_ALLOWLIST:
                continue

            h = AttackHypothesis(
                vuln_class="MissingAuthentication",
                endpoint_id=ep.id,
                description=(
                    f"Write endpoint {ep.method.value} {ep.path} has no "
                    f"authentication requirement detected and is not allowlisted."
                ),
                chain=[ep.id],
                severity_estimate="Critical",
                confidence=0.88,
                evidence=[
                    f"{ep.method.value} {ep.path} — no Depends(auth), no Security()",
                    f"Function: {ep.function_name}",
                ],
                attack_transform=(
                    f"Send {ep.method.value} request to {ep.path} without any "
                    f"Authorization header. Observe if operation succeeds."
                ),
            )
            self.hypotheses.append(h)

    # ── Auth bypass via path asymmetry (corrected) ────────────────────────────
    def _check_auth_bypass_path_asymmetry(self) -> None:
        """
        Pattern: two endpoints share the same resource path prefix,
        one is authenticated, one is not.
        Only flag if the unauthenticated method is a write (POST/PUT/PATCH/DELETE),
        because public read endpoints are normal.
        """
        by_path: dict[str, list[EndpointNode]] = {}
        for ep in self.graph.endpoints():
            by_path.setdefault(ep.path, []).append(ep)

        for path, endpoints in by_path.items():
            if len(endpoints) < 2:
                continue
            auth_set = [e for e in endpoints if e.auth_required]
            noauth_set = [e for e in endpoints if not e.auth_required]
            if not auth_set or not noauth_set:
                continue

            # Only flag if an unauthenticated method is a write
            writes_without_auth = [e for e in noauth_set if e.method in (HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.PATCH, HTTPMethod.DELETE)]
            if not writes_without_auth:
                continue

            for na_ep in writes_without_auth:
                h = AttackHypothesis(
                    vuln_class="AuthBypassPathAsymmetry",
                    endpoint_id=na_ep.id,
                    description=(
                        f"Path asymmetry: {path} enforces auth for "
                        f"{[e.method.value for e in auth_set]} but NOT for "
                        f"{na_ep.method.value} (a write operation)."
                    ),
                    chain=[e.id for e in endpoints],
                    severity_estimate="High",
                    confidence=0.78,
                    evidence=[
                        f"Authenticated methods: {[e.method.value for e in auth_set]}",
                        f"Unauthenticated write method: {na_ep.method.value} {na_ep.path}",
                    ],
                    attack_transform=(
                        f"Access {na_ep.method.value} {path} without credentials. "
                        f"The route handler may perform privileged write operations without "
                        f"the auth guard the {[e.method.value for e in auth_set]} variant has."
                    ),
                )
                self.hypotheses.append(h)

    # ── Unauthenticated write (with allowlist) ─────────────────────────────────
    def _check_unauthenticated_write(self) -> None:
        """
        Pattern: endpoint makes a DB write call (via external call node)
        with no auth context and not allowlisted.
        """
        for ep in self.graph.endpoints():
            if ep.auth_required:
                continue
            if ep.path in PUBLIC_WRITE_ALLOWLIST:
                continue
            for edge in self.graph.outgoing(ep.id):
                if edge.type != EdgeType.CALLS:
                    continue
                ext = self.graph.get_node(edge.dst)
                if not ext or ext.type != NodeType.EXTERNAL:
                    continue
                if ext.metadata.get("call_type", "") not in ("db",):
                    continue
                # Check if it's a write query
                qfrag = getattr(ext, "query_fragment", "").upper()
                if any(w in qfrag for w in ("INSERT", "UPDATE", "DELETE", "CREATE")):
                    h = AttackHypothesis(
                        vuln_class="UnauthenticatedWrite",
                        endpoint_id=ep.id,
                        description=(
                            f"{ep.method.value} {ep.path} performs a DB write "
                            f"without authentication and is not allowlisted."
                        ),
                        chain=[ep.id, ext.id],
                        severity_estimate="Critical",
                        confidence=0.91,
                        evidence=[
                            f"No auth context on {ep.id}",
                            f"DB call: {getattr(ext, 'query_fragment', '')[:80]}",
                        ],
                        attack_transform=(
                            f"POST/PUT to {ep.path} without credentials. "
                            f"Observe database state change."
                        ),
                    )
                    self.hypotheses.append(h)

    # ── Mass assignment remains unchanged ─────────────────────────────────────
    def _check_user_controlled_id_no_ownership(self) -> None:
        """
        Pattern: authenticated endpoint, body param maps to a model field
        that is an ownership marker (user_id, owner_id, tenant_id), but
        no auth context has an ownership constraint.

        Covers two sub-cases:
          A) Direct body param named like an ownership field
          B) Body param is a Pydantic model that *contains* an ownership field
        """
        for ep in self.graph.endpoints():
            if not ep.auth_required:
                continue
            has_ownership_ctx = any(ac.has_ownership_check() for ac in ep.auth_contexts)
            if has_ownership_ctx:
                continue

            for edge in self.graph.incoming(ep.id):
                if edge.type != EdgeType.PARAM_FLOWS_TO:
                    continue
                param = self.graph.get_node(edge.src)
                if not isinstance(param, ParameterNode):
                    continue
                if param.location != ParamLocation.BODY:
                    continue

                # Case A: direct param name is an ownership field
                if any(pattern in param.label.lower()
                       for pattern in ["owner", "user_id", "tenant", "created_by", "account_id"]):
                    self._emit_mass_assignment(ep, param, f"direct body param '{param.label}'")
                    continue

                # Case B: param type is a Pydantic model with ownership fields
                model_id = self.graph._pydantic_models_by_name().get(param.python_type)
                if model_id:
                    model = self.graph.get_node(model_id)
                    if isinstance(model, ModelNode) and model.ownership_fields:
                        self._emit_mass_assignment(
                            ep, param,
                            f"body model '{param.python_type}' contains ownership fields "
                            f"{model.ownership_fields}"
                        )

    def _emit_mass_assignment(self, ep: EndpointNode, param: ParameterNode, reason: str) -> None:
        h = AttackHypothesis(
            vuln_class="MassAssignment",
            endpoint_id=ep.id,
            description=(
                f"Mass assignment: {ep.method.value} {ep.path} — {reason} "
                f"with no server-side ownership enforcement."
            ),
            chain=[param.id, ep.id],
            severity_estimate="High",
            confidence=0.75,
            evidence=[
                f"Reason: {reason}",
                f"No ownership constraint in auth context on {ep.id}",
            ],
            attack_transform=(
                f"Send request to {ep.path} with ownership field set to another "
                f"user's ID. Verify if server accepts and persists it."
            ),
        )
        self.hypotheses.append(h)

    # ── Data leak IDOR (missing ownership on returned model) ───────────────────
    def _check_missing_ownership_on_related_model(self) -> None:
        """
        Pattern: authenticated endpoint returns a model that HAS ownership fields,
        but no auth context constrains by those fields.
        High IDOR signal for read operations (data leak class).
        """
        for ep in self.graph.endpoints():
            if not ep.auth_required:
                continue
            has_ownership_ctx = any(ac.has_ownership_check() for ac in ep.auth_contexts)
            if has_ownership_ctx:
                continue

            # Check response shape edges
            for edge in self.graph.outgoing(ep.id):
                if edge.type != EdgeType.RESPONSE_SHAPE:
                    continue
                model = self.graph.get_node(edge.dst)
                if not isinstance(model, ModelNode):
                    continue
                if not model.ownership_fields:
                    continue

                h = AttackHypothesis(
                    vuln_class="DataLeakIDOR",
                    endpoint_id=ep.id,
                    description=(
                        f"{ep.method.value} {ep.path} returns model '{model.label}' "
                        f"which has ownership fields {model.ownership_fields}, "
                        f"but no ownership constraint enforced in auth."
                    ),
                    chain=[ep.id, model.id],
                    severity_estimate="High",
                    confidence=0.65,
                    evidence=[
                        f"Model '{model.label}' has ownership fields: {model.ownership_fields}",
                        f"Endpoint has no ownership constraint in auth_contexts",
                    ],
                    attack_transform=(
                        f"Access {ep.method.value} {ep.path} as authenticated user. "
                        f"Enumerate IDs in path/query. Verify data belonging to "
                        f"other users is returned."
                    ),
                )
                self.hypotheses.append(h)

    # ── LLM ranking (optional) ────────────────────────────────────────────────
    async def rank_with_llm(self, api_key: Optional[str] = None) -> None:
        """
        Send top candidates to Claude for exploitability scoring.
        Only runs if hypotheses exist. Requires ANTHROPIC_API_KEY env var or api_key param.
        """
        import os
        import aiohttp

        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            print("[llm] No API key — skipping LLM ranking.")
            return

        top = [h for h in self.hypotheses if h.confidence >= 0.5]
        if not top:
            return

        system_prompt = (
            "You are a senior application security researcher. "
            "You will receive a list of potential vulnerability hypotheses derived from "
            "static analysis of a FastAPI application's program state graph. "
            "For each hypothesis, output a JSON array where each element has: "
            "  'endpoint_id': the endpoint ID, "
            "  'llm_score': float 0.0-1.0 (1.0 = near-certain exploitable), "
            "  'llm_narrative': one paragraph attack narrative a pentester would write. "
            "Be conservative. Do not inflate scores for theoretical issues. "
            "Output ONLY valid JSON, no markdown fences."
        )

        user_content = json.dumps([h.to_dict() for h in top], indent=2)

        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 2048,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_content}],
                },
            ) as resp:
                data = await resp.json()

        raw = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                raw += block["text"]

        try:
            ranked = json.loads(raw)
        except json.JSONDecodeError:
            print("[llm] Failed to parse LLM ranking response.")
            return

        score_map = {r["endpoint_id"]: r for r in ranked}
        for h in top:
            if h.endpoint_id in score_map:
                r = score_map[h.endpoint_id]
                h.llm_score = r.get("llm_score")
                h.llm_narrative = r.get("llm_narrative")

        # Re-sort by LLM score where available
        self.hypotheses.sort(
            key=lambda h: (h.llm_score or h.confidence),
            reverse=True
        )
        print(f"[llm] Ranked {len(score_map)} hypotheses.")
