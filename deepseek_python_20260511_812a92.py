# core/chain_reasoner.py
"""
Chain Reasoner — Multi-hop vulnerability detection.

The Hypothesis Engine does single-hop checks (endpoint → auth).
The Chain Reasoner traverses multi-hop paths through the graph to find
broken authorization chains that are 2+ hops deep.

Critical for:
  - Multi-tenant architectures: User → Organization → Workspace → Resource
  - Nested ownership: Company → Department → Project → Task
  - Indirect IDOR through relationships

Integrates directly into HypothesisEngine.run() as an additional check step.
"""

from __future__ import annotations

from collections import deque
from typing import Optional

from core.graph import (
    StateGraph,
    EndpointNode,
    ModelNode,
    ModelFieldNode,
    ParameterNode,
    NodeType,
    EdgeType,
)
from core.hypothesis import AttackHypothesis


# ─── Chain traversal ─────────────────────────────────────────────────────────

class ChainReasoner:
    """
    Finds broken authorization chains by walking MODEL_OWNS and FIELD_OF edges
    from each endpoint's response models back to auth context anchors.
    """

    def __init__(self, graph: StateGraph):
        self.graph = graph

    # ── Ownership Chain Discovery ────────────────────────────────────────

    def find_ownership_chain(
        self,
        model_id: str,
        max_depth: int = 5,
    ) -> list[list[str]]:
        """
        BFS from a model node following ownership-field edges.
        Returns all paths from model → ... → auth-anchored node.
        """
        if not self.graph.get_node(model_id):
            return []

        chains = []
        queue = deque()
        queue.append((model_id, [model_id]))
        visited = {model_id}

        while queue and len(chains) < 20:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue

            # Check if current node has an ownership field that connects to auth
            current_node = self.graph.get_node(current)
            if isinstance(current_node, ModelNode):
                for field_id in current_node.ownership_fields:
                    field_node = self.graph.get_node(field_id)
                    if field_node and isinstance(field_node, ModelFieldNode):
                        # This field represents an ownership link
                        # Check if any endpoint references this model
                        for edge in self.graph.incoming(current):
                            if edge.type == EdgeType.RESPONSE_SHAPE:
                                chains.append(path + ["OWNERSHIP:" + field_id])

            # Walk outgoing FIELD_OF edges to parent models
            for edge in self.graph.outgoing(current):
                if edge.type == EdgeType.FIELD_OF:
                    neighbor = edge.dst
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, path + [neighbor]))

            # Walk into nested models
            for edge in self.graph.incoming(current):
                if edge.type == EdgeType.FIELD_OF:
                    neighbor = edge.src
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, path + [neighbor]))

        return chains

    # ── Chain Completeness Check ──────────────────────────────────────────

    def check_chain_completeness(
        self,
        endpoint_id: str,
        chain: list[str],
    ) -> bool:
        """
        Given a chain from endpoint → ... → ownership field,
        verify that every hop has an auth constraint.
        Returns True if chain is complete (no broken links).
        """
        ep = self.graph.get_node(endpoint_id)
        if not isinstance(ep, EndpointNode):
            return True  # can't verify

        # If endpoint requires no auth, the whole chain is broken
        if not ep.auth_required:
            return False

        # Check if any auth context has an ownership constraint
        has_ownership_constraint = any(
            ac.has_ownership_check() for ac in ep.auth_contexts
        )

        if not has_ownership_constraint:
            # Check if the endpoint's response model has ownership fields
            # that should be constrained
            for edge in self.graph.outgoing(endpoint_id):
                if edge.type == EdgeType.RESPONSE_SHAPE:
                    model = self.graph.get_node(edge.dst)
                    if isinstance(model, ModelNode) and model.ownership_fields:
                        return False  # model has ownership fields but no constraint

        # For each hop in the chain, check if there's a permission boundary
        for i in range(len(chain) - 1):
            current = chain[i]
            next_node = chain[i + 1]
            # Check edges between current and next for auth contexts
            edges_between = [
                e for e in self.graph.outgoing(current)
                if e.dst == next_node
            ]
            for edge in edges_between:
                if edge.auth_contexts:
                    # Has some permission, continue
                    pass
                else:
                    # No permission on this edge — potential broken link
                    if i > 0:  # first hop is endpoint itself, already checked
                        return False

        return True

    # ── Multi-hop Hypothesis Generation ──────────────────────────────────

    def emit_multihop_idor_hypotheses(self) -> list[AttackHypothesis]:
        """
        For every endpoint that returns a model with ownership fields,
        traverse the ownership chain and produce hypotheses for broken links
        that are 2+ hops deep.
        """
        hypotheses = []

        for ep in self.graph.endpoints():
            if not isinstance(ep, EndpointNode):
                continue
            if not ep.auth_required:
                continue

            # Find response models
            for edge in self.graph.outgoing(ep.id):
                if edge.type != EdgeType.RESPONSE_SHAPE:
                    continue
                model = self.graph.get_node(edge.dst)
                if not isinstance(model, ModelNode):
                    continue
                if not model.ownership_fields:
                    continue

                # Find ownership chain
                chains = self.find_ownership_chain(model.id)
                for chain in chains:
                    if len(chain) < 3:
                        continue  # only interested in multi-hop

                    is_complete = self.check_chain_completeness(ep.id, chain)
                    if not is_complete:
                        # Find the specific broken link
                        broken_hop = self._find_broken_hop(chain)
                        if broken_hop:
                            h = AttackHypothesis(
                                vuln_class="MultiHopIDOR",
                                endpoint_id=ep.id,
                                description=(
                                    f"Multi-hop authorization bypass: {ep.method.value} {ep.path} "
                                    f"returns model '{model.label}' with ownership chain "
                                    f"{' → '.join(chain[:3])}... — broken at {broken_hop}"
                                ),
                                chain=[ep.id, model.id] + chain[:3],
                                severity_estimate="Critical",
                                confidence=0.6,
                                evidence=[
                                    f"Response model: {model.label}",
                                    f"Ownership fields: {model.ownership_fields}",
                                    f"Chain length: {len(chain)} hops",
                                    f"Broken at: {broken_hop}",
                                    f"No ownership constraint in auth_contexts: {not any(ac.has_ownership_check() for ac in ep.auth_contexts)}",
                                ],
                                attack_transform=(
                                    f"Access {ep.method.value} {ep.path} as a low-privilege user. "
                                    f"Traverse the relationship chain through {broken_hop} to reach "
                                    f"resources belonging to other tenants or organizations."
                                ),
                            )
                            hypotheses.append(h)

        return hypotheses

    def _find_broken_hop(self, chain: list[str]) -> Optional[str]:
        """Identify which hop in the chain lacks an auth constraint."""
        if len(chain) < 2:
            return None

        for i in range(len(chain) - 1):
            current = chain[i]
            next_node = chain[i + 1]
            edges = [
                e for e in self.graph.outgoing(current)
                if e.dst == next_node
            ]
            if not edges or not any(e.auth_contexts for e in edges):
                return f"{current} → {next_node}"
        return chain[-2] if len(chain) >= 2 else None

    # ── Direct IDOR from relationship endpoints ──────────────────────────

    def find_relationship_idor(self) -> list[AttackHypothesis]:
        """
        Find endpoints that operate on relationship resources
        (e.g., /orgs/{org_id}/members/{user_id}) where only one of the
        parent IDs is authorized.
        """
        hypotheses = []

        # Find endpoints with multiple path params
        for ep in self.graph.endpoints():
            if not isinstance(ep, EndpointNode):
                continue
            if not ep.auth_required:
                continue

            # Count path params
            path_params = []
            for edge in self.graph.incoming(ep.id):
                if edge.type == EdgeType.PARAM_FLOWS_TO:
                    param = self.graph.get_node(edge.src)
                    if isinstance(param, ParameterNode) and param.location.value == "path":
                        path_params.append(param)

            if len(path_params) < 2:
                continue

            # Check if any path param is an ID without ownership verification
            id_params = [p for p in path_params if any(
                k in p.label.lower() for k in ["_id", "id", "uuid", "key"]
            )]

            if len(id_params) >= 2:
                has_ownership = any(
                    ac.has_ownership_check() for ac in ep.auth_contexts
                )
                if not has_ownership:
                    h = AttackHypothesis(
                        vuln_class="RelationshipIDOR",
                        endpoint_id=ep.id,
                        description=(
                            f"Relationship IDOR: {ep.path} has multiple ID path params "
                            f"({[p.label for p in id_params]}) with no ownership constraint. "
                            f"Attacker may traverse nested resources."
                        ),
                        chain=[p.id for p in id_params] + [ep.id],
                        severity_estimate="High",
                        confidence=0.7,
                        evidence=[
                            f"Path params: {[p.label for p in path_params]}",
                            f"ID params: {[p.label for p in id_params]}",
                            f"No ownership constraint in auth",
                        ],
                        attack_transform=(
                            f"Replace one or more ID params with values from other "
                            f"organizations/users while keeping the parent scope ID valid."
                        ),
                    )
                    hypotheses.append(h)

        return hypotheses

    # ── Integration ──────────────────────────────────────────────────────

    def run_all_checks(self) -> list[AttackHypothesis]:
        """Run all chain-based checks and return hypotheses."""
        hypotheses = []
        hypotheses.extend(self.emit_multihop_idor_hypotheses())
        hypotheses.extend(self.find_relationship_idor())
        return hypotheses