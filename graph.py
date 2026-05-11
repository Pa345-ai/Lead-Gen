"""
State Graph — the truth layer.

Every node and edge carries an auth_contexts dimension as a first-class
property, not an afterthought. This is the key design decision that enables
chain reasoning across permission boundaries.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
import json


# ─── Enums ───────────────────────────────────────────────────────────────────

class NodeType(str, Enum):
    ENDPOINT  = "Endpoint"
    PARAMETER = "Parameter"
    MODEL     = "DataModel"
    FIELD     = "ModelField"
    PERMISSION= "Permission"
    EXTERNAL  = "ExternalCall"


class EdgeType(str, Enum):
    PARAM_FLOWS_TO   = "parameter_flows_to"   # param → model field / DB query
    ENDPOINT_REQUIRES= "endpoint_requires"     # endpoint → permission
    MODEL_OWNS       = "model_owns"            # model → ownership field
    CALLS            = "calls"                 # endpoint → external service
    FIELD_OF         = "field_of"              # field → parent model
    RESPONSE_SHAPE   = "response_shape"        # endpoint → returned model


class HTTPMethod(str, Enum):
    GET    = "GET"
    POST   = "POST"
    PUT    = "PUT"
    PATCH  = "PATCH"
    DELETE = "DELETE"
    ANY    = "ANY"


class ParamLocation(str, Enum):
    PATH   = "path"
    QUERY  = "query"
    BODY   = "body"
    HEADER = "header"
    COOKIE = "cookie"


# ─── Auth Context ─────────────────────────────────────────────────────────────

@dataclass
class AuthContext:
    """
    A single (role, constraint) tuple on an edge.
    constraint=None means unrestricted for that role.
    constraint="DENY" means explicitly forbidden.
    constraint="<expr>" is a Python-like ownership expression, e.g.
        "object.owner_id == jwt.sub"
    """
    role: str
    constraint: Optional[str]
    source: str = ""           # where we saw this (decorator name, dependency fn)
    confidence: float = 1.0   # 0.0–1.0; drops when inferred rather than explicit

    def is_unrestricted(self) -> bool:
        return self.constraint is None

    def is_denied(self) -> bool:
        return self.constraint == "DENY"

    def has_ownership_check(self) -> bool:
        if not self.constraint or self.constraint == "DENY":
            return False
        ownership_keywords = ["owner", "user_id", "sub", "tenant", "created_by"]
        return any(k in self.constraint.lower() for k in ownership_keywords)

    def to_dict(self) -> dict:
        return {
            "role": self.role,
            "constraint": self.constraint,
            "source": self.source,
            "confidence": self.confidence,
        }


# ─── Nodes ───────────────────────────────────────────────────────────────────

@dataclass
class Node:
    id: str              # stable unique key, e.g. "endpoint:/api/order/{id}:GET"
    type: NodeType
    label: str           # human-readable
    file: str = ""
    line: int = 0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "label": self.label,
            "file": self.file,
            "line": self.line,
            "metadata": self.metadata,
        }


@dataclass
class EndpointNode(Node):
    type: NodeType = field(default=NodeType.ENDPOINT, init=False)
    method: HTTPMethod = HTTPMethod.GET
    path: str = ""
    function_name: str = ""
    auth_contexts: list[AuthContext] = field(default_factory=list)
    auth_required: bool = False

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "method": self.method.value,
            "path": self.path,
            "function_name": self.function_name,
            "auth_required": self.auth_required,
            "auth_contexts": [a.to_dict() for a in self.auth_contexts],
        })
        return d


@dataclass
class ParameterNode(Node):
    type: NodeType = field(default=NodeType.PARAMETER, init=False)
    location: ParamLocation = ParamLocation.QUERY
    python_type: str = "Any"
    required: bool = True
    default: Any = None
    user_controlled: bool = True

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "location": self.location.value,
            "python_type": self.python_type,
            "required": self.required,
            "default": self.default,
            "user_controlled": self.user_controlled,
        })
        return d


@dataclass
class ModelNode(Node):
    type: NodeType = field(default=NodeType.MODEL, init=False)
    fields: list[str] = field(default_factory=list)
    ownership_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "fields": self.fields,
            "ownership_fields": self.ownership_fields,
        })
        return d


@dataclass
class ModelFieldNode(Node):
    type: NodeType = field(default=NodeType.FIELD, init=False)
    field_type: str = "Any"
    parent_model: str = ""
    is_ownership_marker: bool = False

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "field_type": self.field_type,
            "parent_model": self.parent_model,
            "is_ownership_marker": self.is_ownership_marker,
        })
        return d


@dataclass
class PermissionNode(Node):
    type: NodeType = field(default=NodeType.PERMISSION, init=False)
    dependency_fn: str = ""
    inferred_role: str = "user"
    scope: Optional[str] = None

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "dependency_fn": self.dependency_fn,
            "inferred_role": self.inferred_role,
            "scope": self.scope,
        })
        return d


@dataclass
class ExternalCallNode(Node):
    type: NodeType = field(default=NodeType.EXTERNAL, init=False)
    call_type: str = "db"
    query_fragment: str = ""

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "call_type": self.call_type,
            "query_fragment": self.query_fragment,
        })
        return d


# ─── Edges ───────────────────────────────────────────────────────────────────

@dataclass
class Edge:
    src: str           # source node ID
    dst: str           # destination node ID
    type: EdgeType
    # Auth contexts on THIS edge — what permission level does this traversal imply?
    auth_contexts: list[AuthContext] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.src}--{self.type.value}-->{self.dst}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "src": self.src,
            "dst": self.dst,
            "type": self.type.value,
            "auth_contexts": [a.to_dict() for a in self.auth_contexts],
            "metadata": self.metadata,
        }


# ─── Graph ───────────────────────────────────────────────────────────────────

class StateGraph:
    """
    The unified program state graph.

    Nodes:  Endpoints, Parameters, Models, Fields, Permissions, ExternalCalls
    Edges:  typed relationships with per-edge auth context tuples
    """

    def __init__(self):
        self._nodes: dict[str, Node] = {}
        self._edges: dict[str, Edge] = {}
        self._adj: dict[str, list[str]] = {}   # src → [edge_ids]
        self._radj: dict[str, list[str]] = {}  # dst → [edge_ids]

    # ── Mutation ─────────────────────────────────────────────────────────────

    def add_node(self, node: Node) -> None:
        self._nodes[node.id] = node
        if node.id not in self._adj:
            self._adj[node.id] = []
        if node.id not in self._radj:
            self._radj[node.id] = []

    def add_edge(self, edge: Edge) -> None:
        # Ensure both endpoints exist (ghost nodes for forward refs)
        for nid in (edge.src, edge.dst):
            if nid not in self._nodes:
                self._nodes[nid] = Node(id=nid, type=NodeType.ENDPOINT, label=nid)
                self._adj[nid] = []
                self._radj[nid] = []

        self._edges[edge.id] = edge
        self._adj[edge.src].append(edge.id)
        self._radj[edge.dst].append(edge.id)

    # ── Query ─────────────────────────────────────────────────────────────────

    def get_node(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id)

    def outgoing(self, node_id: str) -> list[Edge]:
        return [self._edges[eid] for eid in self._adj.get(node_id, [])]

    def incoming(self, node_id: str) -> list[Edge]:
        return [self._edges[eid] for eid in self._radj.get(node_id, [])]

    def nodes_by_type(self, t: NodeType) -> list[Node]:
        return [n for n in self._nodes.values() if n.type == t]

    def endpoints(self) -> list[EndpointNode]:
        return [n for n in self._nodes.values() if isinstance(n, EndpointNode)]

    def find_edges(self, edge_type: EdgeType) -> list[Edge]:
        return [e for e in self._edges.values() if e.type == edge_type]

    def _pydantic_models_by_name(self) -> dict[str, str]:
        """Return {class_name: node_id} for all ModelNode instances."""
        return {
            n.label: n.id
            for n in self._nodes.values()
            if isinstance(n, ModelNode)
        }

    # ── Stats ─────────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        by_type: dict[str, int] = {}
        for n in self._nodes.values():
            k = n.type.value
            by_type[k] = by_type.get(k, 0) + 1
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "by_node_type": by_type,
        }

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "nodes": {nid: n.to_dict() for nid, n in self._nodes.items()},
            "edges": {eid: e.to_dict() for eid, e in self._edges.items()},
            "summary": self.summary(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            f.write(self.to_json())
        print(f"[graph] Saved {len(self._nodes)} nodes, {len(self._edges)} edges → {path}")
