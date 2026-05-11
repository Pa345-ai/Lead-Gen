"""
Dynamic Observer – Phase 4 Final ("Omni-Observer") – Polished (v2)

Refinements over previous version:
  1. Content‑Type gatekeeping – skip non‑JSON traffic entirely.
  2. Smarter path normalisation – Shannon entropy + short alphanumeric ID detection.
  3. Asynchronous graph persistence – auto‑save every 60 seconds.
  4. Short alphanumeric IDs (like 5kL9) now correctly treated as {id}.

All existing features retained.
"""

from __future__ import annotations

import asyncio
import base64
import json
import math
import re
import time
import uuid
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from mitmproxy import ctx, http

from core.graph import (
    StateGraph,
    NodeType,
    EdgeType,
    HTTPMethod,
    ParamLocation,
    EndpointNode,
    ParameterNode,
    ModelNode,
    ModelFieldNode,
    PermissionNode,
    AuthContext,
    Edge,
)

# ─── Constants ───────────────────────────────────────────────────────────────
DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_SAVE_PATH = "observer_graph.json"
DEFAULT_SAVE_INTERVAL_SEC = 60
DEFAULT_ROLE_HEADERS = {
    "x-role": "role",
    "x-api-key": "api_key",
}
ROLE_RESPONSE_CACHE_SIZE = 3
MAX_ID_REGISTRY_SIZE = 5000
MAX_ROLE_CACHE_SIZE = 2000

# Entropy threshold for distinguishing static slugs from high‑entropy IDs
ENTROPY_THRESHOLD = 3.2


# ─── LRU Cache helper ────────────────────────────────────────────────────────

class LRUDict(OrderedDict):
    def __init__(self, maxsize: int = 1000, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.maxsize = maxsize

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if len(self) > self.maxsize:
            self.popitem(last=False)


# ─── Trace data models ───────────────────────────────────────────────────────

@dataclass
class TraceStep:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    method: str = ""
    url: str = ""
    path_template: str = ""
    concrete_path: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    elapsed_ms: float = 0.0
    inferred_user_role: Optional[str] = None
    auth_type: Optional[str] = None
    path_params: dict[str, str] = field(default_factory=dict)
    query_params: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class StructuredTrace:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    steps: list[TraceStep] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)


# ─── Utility functions ───────────────────────────────────────────────────────

def _calculate_shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _is_likely_slug(segment: str) -> bool:
    """
    Returns True if the segment looks like a static resource name
    (words, hyphens, underscores) rather than a high‑entropy ID.
    """
    # Common static pattern: lowercase letters, optional hyphens/underscores, optional trailing digits
    if re.fullmatch(r'[a-z]+(?:[-_][a-z]+)*\d*', segment):
        return True
    # Mixed case but still word‑ish (e.g., "UserSettings")
    if re.fullmatch(r'[a-zA-Z]+(?:[-_][a-zA-Z]+)*', segment):
        return True
    # Otherwise check entropy
    entropy = _calculate_shannon_entropy(segment)
    return entropy < ENTROPY_THRESHOLD


def normalize_path(url_path: str) -> str:
    """
    Segment‑based normalisation with entropy filter and short‑ID detection.
    - UUIDs → {uuid}
    - Pure digits → {id}
    - Short alphanumeric (≤5 chars, contains digit + letter) → {id}
    - High‑entropy long segments → {id}
    - Low‑entropy wordy segments remain untouched.
    """
    parts = url_path.strip("/").split("/")
    normalized = []
    for part in parts:
        # UUID (v4)
        if re.fullmatch(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', part, re.IGNORECASE
        ):
            normalized.append("{uuid}")
        # Pure numeric ID
        elif part.isdigit():
            normalized.append("{id}")
        # Short alphanumeric ID (e.g., "5kL9") – length ≤ 5, contains both digits and letters
        elif len(part) <= 5 and re.search(r'\d', part) and re.search(r'[a-zA-Z]', part):
            normalized.append("{id}")
        # Long high‑entropy segment (likely random)
        elif len(part) > 8 and not _is_likely_slug(part):
            normalized.append("{id}")
        else:
            normalized.append(part)

    # Deduplicate placeholders (e.g., /{id}/{id} → /{id}/{id2})
    seen = {}
    final = []
    for part in normalized:
        if part in ("{id}", "{uuid}"):
            seen.setdefault(part, 0)
            seen[part] += 1
            if seen[part] > 1:
                final.append(f"{{{part[1:-1]}{seen[part]}}}")
            else:
                final.append(part)
        else:
            final.append(part)
    return "/" + "/".join(final)


def infer_json_schema(
    js: Any, parent_key: str = "root", depth: int = 0, max_depth: int = 3
) -> dict:
    if depth > max_depth:
        return {"type": "any", "fields": {}}
    if isinstance(js, dict):
        schema = {"type": "object", "fields": {}}
        for k, v in js.items():
            schema["fields"][k] = infer_json_schema(v, k, depth + 1, max_depth)
        return schema
    elif isinstance(js, list):
        if js:
            item_schema = infer_json_schema(js[0], "items", depth + 1, max_depth)
        else:
            item_schema = {"type": "any", "fields": {}}
        return {"type": "array", "items": item_schema, "fields": {}}
    elif isinstance(js, bool):
        return {"type": "boolean", "fields": {}}
    elif isinstance(js, int):
        return {"type": "integer", "fields": {}}
    elif isinstance(js, float):
        return {"type": "number", "fields": {}}
    elif isinstance(js, str):
        return {"type": "string", "fields": {}}
    else:
        return {"type": "any", "fields": {}}


def detect_sensitive_fields(js: dict) -> list[str]:
    keywords = ["admin", "role", "owner", "user_id", "email", "token", "secret", "key"]
    return [k for k in js if any(kw in k.lower() for kw in keywords)]


def decode_jwt_payload(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes)
    except Exception:
        return None


def guess_auth_context(request_headers: dict, base_url: str = "") -> tuple[Optional[str], Optional[str]]:
    auth = request_headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:]
        payload = decode_jwt_payload(token)
        role = "user"
        if payload:
            role = payload.get("role") or payload.get("scope") or payload.get("sub") or "user"
            if any("admin" in str(v).lower() for v in payload.values() if isinstance(v, str)):
                role = "admin"
        return role, "bearer"
    cookie = request_headers.get("cookie", "")
    if "session" in cookie:
        return "user", "cookie"
    for header, role_name in DEFAULT_ROLE_HEADERS.items():
        if header in request_headers:
            return request_headers[header], "api_key"
    return "anonymous", None


# ─── Dynamic Observer mitmproxy addon ────────────────────────────────────────

class DynamicObserver:
    def __init__(self):
        self.pending: dict[str, TraceStep] = {}
        self.traces: list[StructuredTrace] = []
        self.current_session = StructuredTrace()
        self.graph = StateGraph()
        self.base_url = DEFAULT_BASE_URL
        self.save_path = DEFAULT_SAVE_PATH
        self.save_interval = DEFAULT_SAVE_INTERVAL_SEC
        self.process_queue: asyncio.Queue = asyncio.Queue()
        self.processing_task: Optional[asyncio.Task] = None
        self.save_task: Optional[asyncio.Task] = None

        # Caches with LRU
        self.role_response_cache: dict[tuple[str, str], dict[str, list[dict]]] = LRUDict(
            maxsize=MAX_ROLE_CACHE_SIZE
        )
        self.created_resources: LRUDict[str, tuple[str, str]] = LRUDict(
            maxsize=MAX_ID_REGISTRY_SIZE
        )

    def load(self, loader):
        loader.add_option(
            name="observer_base_url",
            typespec=str,
            default=DEFAULT_BASE_URL,
            help="Base URL of the target API",
        )
        loader.add_option(
            name="observer_save_path",
            typespec=str,
            default=DEFAULT_SAVE_PATH,
            help="Path where the observer graph will be periodically saved",
        )
        loader.add_option(
            name="observer_save_interval",
            typespec=int,
            default=DEFAULT_SAVE_INTERVAL_SEC,
            help="Interval in seconds for auto‑saving the graph",
        )

    def running(self):
        self.base_url = ctx.options.observer_base_url
        self.save_path = ctx.options.observer_save_path
        self.save_interval = ctx.options.observer_save_interval
        self.processing_task = asyncio.ensure_future(self._process_queue())
        self.save_task = asyncio.ensure_future(self._auto_save_loop())

    def done(self):
        for task in [self.processing_task, self.save_task]:
            if task and not task.done():
                task.cancel()
        self._save_graph_to_disk()

    def request(self, flow: http.HTTPFlow):
        concrete_path = urlparse(flow.request.url).path
        step = TraceStep(
            method=flow.request.method,
            url=flow.request.pretty_url,
            path_template=normalize_path(concrete_path),
            concrete_path=concrete_path,
            request_headers=dict(flow.request.headers),
            request_body=flow.request.text if flow.request.content else None,
        )
        step.path_params = self._extract_path_params(step.path_template, concrete_path)
        step.query_params = dict(urlparse(flow.request.url).query_params)
        self.pending[flow.id] = step

    def response(self, flow: http.HTTPFlow):
        step = self.pending.pop(flow.id, None)
        if not step:
            return

        # Content‑Type gatekeeping: only process JSON traffic
        content_type = flow.response.headers.get("Content-Type", "").lower()
        if "json" not in content_type:
            self.current_session.add(step)
            return

        step.response_status = flow.response.status_code
        step.response_headers = dict(flow.response.headers)
        step.response_body = flow.response.text if flow.response.content else None
        step.elapsed_ms = (time.time() - step.timestamp) * 1000

        role, auth_type = guess_auth_context(step.request_headers, self.base_url)
        step.inferred_user_role = role
        step.auth_type = auth_type

        # Location header tracking
        if step.response_status in (200, 201):
            location = step.response_headers.get("location", "")
            if location:
                if not location.startswith("http"):
                    location = urljoin(self.base_url, location)
                loc_path = urlparse(location).path
                loc_template = normalize_path(loc_path)
                loc_concrete = urlparse(location).path
                params = self._extract_path_params(loc_template, loc_concrete)
                if params:
                    resource_id = list(params.values())[0]
                    self.created_resources[resource_id] = (
                        f"endpoint:{step.path_template}:{step.method}",
                        step.path_template,
                    )

        self.current_session.add(step)
        self.process_queue.put_nowait(step)

    def _extract_path_params(self, template: str, concrete: str) -> dict[str, str]:
        params = {}
        t_parts = template.strip("/").split("/")
        c_parts = concrete.strip("/").split("/")
        for i in range(min(len(t_parts), len(c_parts))):
            if t_parts[i].startswith("{") and t_parts[i].endswith("}"):
                key = t_parts[i][1:-1]
                params[key] = c_parts[i]
        return params

    async def _process_queue(self):
        while True:
            try:
                step = await self.process_queue.get()
                self._integrate_step(step)
                self.process_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                ctx.log.error(f"Observer processing error: {e}")

    async def _auto_save_loop(self):
        while True:
            try:
                await asyncio.sleep(self.save_interval)
                self._save_graph_to_disk()
            except asyncio.CancelledError:
                break
            except Exception as e:
                ctx.log.error(f"Auto‑save error: {e}")

    def _save_graph_to_disk(self):
        try:
            self.graph.save(self.save_path)
            ctx.log.info(f"[observer] Graph saved to {self.save_path}")
        except Exception as e:
            ctx.log.error(f"[observer] Failed to save graph: {e}")

    # ── Core integration ─────────────────────────────────────────────────────

    def _integrate_step(self, step: TraceStep):
        ep_id = f"endpoint:{step.path_template}:{step.method}"
        ep = self.graph.get_node(ep_id)
        if not ep:
            ep = EndpointNode(
                id=ep_id,
                label=f"{step.method} {step.path_template}",
                method=HTTPMethod(step.method.upper()),
                path=step.path_template,
                function_name="dynamic",
                auth_required=step.inferred_user_role != "anonymous",
            )
            self.graph.add_node(ep)

        # Auth context
        if step.inferred_user_role and step.inferred_user_role != "anonymous":
            ac = AuthContext(
                role=step.inferred_user_role,
                constraint=None,
                source=f"observed-{step.auth_type}",
                confidence=0.95,
            )
            if ac not in ep.auth_contexts:
                ep.auth_contexts.append(ac)
                perm_id = f"perm:{ac.source}"
                if not self.graph.get_node(perm_id):
                    self.graph.add_node(PermissionNode(
                        id=perm_id, label=ac.source,
                        dependency_fn=ac.source, inferred_role=ac.role
                    ))
                self.graph.add_edge(Edge(
                    src=ep_id, dst=perm_id, type=EdgeType.ENDPOINT_REQUIRES,
                    auth_contexts=[ac],
                ))

        # Query params
        for k in step.query_params:
            self._add_param(ep_id, k, ParamLocation.QUERY, "str", False, ep.auth_contexts)

        # Path params
        for var in step.path_params:
            self._add_param(ep_id, var, ParamLocation.PATH, "str", True, ep.auth_contexts)

        # Recursive model inference (only for JSON responses)
        if step.response_body:
            try:
                resp_js = json.loads(step.response_body)
                if isinstance(resp_js, (dict, list)):
                    model_id = self._create_model_tree(resp_js, step.path_template)
                    if model_id:
                        self.graph.add_edge(Edge(
                            src=ep_id, dst=model_id, type=EdgeType.RESPONSE_SHAPE
                        ))
            except Exception:
                pass

        # Shadow parameters
        if step.request_body and step.response_body:
            try:
                req_js = json.loads(step.request_body) if step.request_headers.get("content-type", "").startswith("application/json") else None
                resp_js = json.loads(step.response_body)
                if isinstance(req_js, dict) and isinstance(resp_js, dict):
                    shadow_keys = set(resp_js.keys()) - set(req_js.keys())
                    for sk in shadow_keys:
                        param_id = f"param:{ep_id}:shadow_{sk}"
                        if not self.graph.get_node(param_id):
                            pn = ParameterNode(
                                id=param_id, label=f"shadow:{sk}",
                                location=ParamLocation.BODY,
                                python_type=type(resp_js[sk]).__name__,
                                required=False, user_controlled=False,
                                metadata={"discovered": "shadow_param"},
                            )
                            self.graph.add_node(pn)
                            self.graph.add_edge(Edge(
                                src=param_id, dst=ep_id,
                                type=EdgeType.PARAM_FLOWS_TO,
                                auth_contexts=ep.auth_contexts,
                            ))
            except Exception:
                pass

        # Timing baselining
        if step.elapsed_ms < 10 and step.response_status in (200, 201):
            ctx.log.info(
                f"Possible timing leak: fast response on {step.url} ({step.elapsed_ms:.1f}ms)"
            )

        # Multi‑user response comparison
        self._cache_role_response(step)
        self._detect_privilege_drift(step)

        # State dependency tracking
        self._track_state_dependency(step)

    def _add_param(self, ep_id: str, name: str, location: ParamLocation,
                   python_type: str, required: bool, auth_contexts: list):
        param_id = f"param:{ep_id}:{name}"
        if not self.graph.get_node(param_id):
            self.graph.add_node(ParameterNode(
                id=param_id, label=name, location=location,
                python_type=python_type, required=required, user_controlled=True,
            ))
            self.graph.add_edge(Edge(
                src=param_id, dst=ep_id, type=EdgeType.PARAM_FLOWS_TO,
                auth_contexts=auth_contexts,
            ))

    # ── Recursive model builder ────────────────────────────────────

    def _create_model_tree(self, data: Any, path_hint: str,
                           parent_model_id: Optional[str] = None,
                           field_name: str = "root",
                           depth: int = 0) -> Optional[str]:
        if depth > 3:
            return None
        if isinstance(data, dict):
            model_name = f"DynamicModel_{path_hint.replace('/', '_')}_{uuid.uuid4().hex[:6]}"
            model_id = f"model:{model_name}"
            if depth == 0:
                model_id = f"model:{path_hint.replace('/', '_')}_response"
            if self.graph.get_node(model_id):
                return model_id

            fields = []
            for k, v in data.items():
                ftype = "string"
                child_model_id = None
                if isinstance(v, dict):
                    child_model_id = self._create_model_tree(
                        v, path_hint, parent_model_id=model_id, field_name=k, depth=depth+1
                    )
                    ftype = child_model_id or "object"
                elif isinstance(v, list):
                    child_model_id = self._create_model_tree(
                        v, path_hint, parent_model_id=model_id, field_name=k, depth=depth+1
                    )
                    ftype = child_model_id or "array"
                elif isinstance(v, int):
                    ftype = "integer"
                elif isinstance(v, float):
                    ftype = "number"
                elif isinstance(v, bool):
                    ftype = "boolean"
                else:
                    ftype = "string"

                fid = f"field:{model_name}.{k}"
                is_own = any(kw in k.lower() for kw in ["user_id", "owner_id", "tenant_id"])
                fnode = ModelFieldNode(
                    id=fid, label=k, field_type=ftype,
                    parent_model=model_id, is_ownership_marker=is_own,
                )
                self.graph.add_node(fnode)
                fields.append(fid)
                self.graph.add_edge(Edge(src=fid, dst=model_id, type=EdgeType.FIELD_OF))
                if child_model_id:
                    fnode.metadata["nested_model"] = child_model_id

            model_node = ModelNode(
                id=model_id, label=model_name,
                fields=fields,
                ownership_fields=[f for f in fields if
                                  self.graph.get_node(f).is_ownership_marker],
            )
            self.graph.add_node(model_node)
            return model_id
        elif isinstance(data, list):
            if data:
                return self._create_model_tree(data[0], path_hint,
                                               parent_model_id=parent_model_id,
                                               field_name=field_name, depth=depth)
            return None
        else:
            return None

    # ── Multi‑user response caching & drift detection ─────────────────

    def _cache_role_response(self, step: TraceStep):
        if not step.response_body:
            return
        try:
            body = json.loads(step.response_body)
        except Exception:
            return
        key = (step.path_template, step.method)
        role = step.inferred_user_role or "anonymous"
        if key not in self.role_response_cache:
            self.role_response_cache[key] = {}
        if role not in self.role_response_cache[key]:
            self.role_response_cache[key][role] = []
        role_list = self.role_response_cache[key][role]
        role_list.append(body)
        if len(role_list) > ROLE_RESPONSE_CACHE_SIZE:
            role_list.pop(0)

    def _detect_privilege_drift(self, step: TraceStep):
        key = (step.path_template, step.method)
        if key not in self.role_response_cache:
            return
        current_role = step.inferred_user_role or "anonymous"
        cache = self.role_response_cache[key]
        if len(cache) < 2:
            return
        latest_own = cache.get(current_role, [None])[-1]
        if latest_own is None:
            return
        for other_role, responses in cache.items():
            if other_role == current_role:
                continue
            other = responses[-1] if responses else None
            if other is None:
                continue
            own_keys = set(latest_own.keys()) if isinstance(latest_own, dict) else set()
            other_keys = set(other.keys()) if isinstance(other, dict) else set()
            only_own = own_keys - other_keys
            only_other = other_keys - own_keys
            if only_own or only_other:
                ctx.log.info(
                    f"[Privilege Drift] {step.path_template} ({current_role} vs {other_role}): "
                    f"exclusive keys: current_role={only_own}, other_role={only_other}"
                )
                ep_id = f"endpoint:{step.path_template}:{step.method}"
                ep = self.graph.get_node(ep_id)
                if ep and isinstance(ep, EndpointNode):
                    if "privilege_gated_fields" not in ep.metadata:
                        ep.metadata["privilege_gated_fields"] = []
                    for f in only_own:
                        ep.metadata["privilege_gated_fields"].append(f)
                        for model_field in self.graph.nodes_by_type(NodeType.FIELD):
                            if model_field.label == f:
                                model_field.metadata["privilege_gated"] = True

    # ── State dependency tracking ───────────────────────────────

    def _track_state_dependency(self, step: TraceStep):
        ep_id = f"endpoint:{step.path_template}:{step.method}"
        method = step.method.upper()

        if method in ("POST", "PUT") and step.response_status in (200, 201):
            resource_id = None
            if not resource_id and step.response_body:
                try:
                    body = json.loads(step.response_body)
                    if isinstance(body, dict):
                        for id_candidate in ("id", "uuid", "key"):
                            if id_candidate in body:
                                resource_id = str(body[id_candidate])
                                break
                except Exception:
                    pass
            if resource_id and resource_id not in self.created_resources:
                self.created_resources[resource_id] = (ep_id, step.path_template)

        elif method in ("GET", "PUT", "PATCH", "DELETE"):
            for var_name, var_value in step.path_params.items():
                if var_value in self.created_resources:
                    creator_ep_id, creator_template = self.created_resources[var_value]
                    edge_id = f"{creator_ep_id}--state_depends--{ep_id}"
                    if not self.graph.get_node(edge_id):
                        self.graph.add_edge(Edge(
                            src=creator_ep_id,
                            dst=ep_id,
                            type=EdgeType.CALLS,
                            metadata={
                                "dependency_type": "resource_provided",
                                "resource_id": var_value,
                            },
                        ))

    # ── Bulk export helpers ─────────────────────────────────────────

    def build_graph_summary(self) -> dict:
        return self.graph.summary()

    def save_graph(self, path: str):
        self.graph.save(path)


# ─── Optional Lightweight Spider ────────────────────────────────────────────

class LightweightSpider:
    def __init__(self, base_url: str, observer: DynamicObserver):
        self.base_url = base_url
        self.observer = observer

    async def crawl_from_seed(self, seed_url: str):
        import httpx
        async with httpx.AsyncClient(base_url=self.base_url) as client:
            visited = set()
            to_visit = [seed_url]
            while to_visit:
                url = to_visit.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                try:
                    resp = await client.get(url)
                    if "location" in resp.headers:
                        next_url = urljoin(self.base_url, resp.headers["location"])
                        to_visit.append(next_url)
                except Exception:
                    pass


# ─── Integration: merge observed graph into main StateGraph ──────────────────

def merge_dynamic_graph(static_graph: StateGraph, observer: DynamicObserver) -> StateGraph:
    for nid, node in observer.graph._nodes.items():
        existing = static_graph.get_node(nid)
        if not existing:
            static_graph.add_node(node)
        else:
            if hasattr(existing, 'metadata'):
                existing.metadata['observed'] = True
    for eid, edge in observer.graph._edges.items():
        if not static_graph.get_node(eid):
            static_graph.add_edge(edge)
    return static_graph
