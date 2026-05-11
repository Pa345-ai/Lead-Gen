"""
Exploit Verification Engine (Executor) – Phase 3 (Enterprise-Grade) Final

Refinements over previous iteration:
  - Recursion depth guard for nested model generation (prevents infinite loops).
  - Defensive null‑check for response text in default success oracle.
  
All original features retained:
  - Namespaced stored data, recursive schema‑driven payloads (UUID/email/datetime).
  - Cookie & custom header identity store.
  - Multi‑factor success oracle (2xx + blacklist + mandatory JSON paths).
  - Short‑circuit on setup failure; differential IDOR/Mass Assignment proving.
  - Teardown error capture and reporting.
"""

from __future__ import annotations

import asyncio
import copy
import json
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from http.cookiejar import CookieJar
from typing import Any, Callable, Optional
from urllib.parse import urljoin

import httpx

from core.graph import (
    StateGraph,
    EndpointNode,
    ParameterNode,
    ModelNode,
    ModelFieldNode,
    NodeType,
    EdgeType,
    HTTPMethod,
    ParamLocation,
)
from core.hypothesis import AttackHypothesis


# ─── Enums & constants ──────────────────────────────────────────────────────

class ImpactLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    DISPROVED = "disproved"
    INCONCLUSIVE = "inconclusive"


_DEFAULT_ORACLE_BLACKLIST = ["error", "denied", "unauthorized", "forbidden", "invalid"]

# Maximum nesting depth for recursive model generation
MAX_NESTING_DEPTH = 5


# ─── JSON path helpers ─────────────────────────────────────────────────────

def _json_path_get(data: Any, path: str) -> Any:
    """Retrieve value at dot‑separated path inside nested dicts."""
    parts = path.lstrip("$").strip(".").split(".")
    if not parts or parts == [""]:
        return data
    current = data
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            current = current[int(part)]
        else:
            return None
    return current


def _json_path_set(data: dict, path: str, value: Any) -> None:
    """Set a value deep inside a nested dict, creating intermediate dicts."""
    parts = path.lstrip("$").strip(".").split(".")
    if not parts:
        return
    current = data
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value


# ─── Credential / session store ─────────────────────────────────────────────

@dataclass
class IdentityContext:
    """Full authentication context for a role."""
    headers: dict = field(default_factory=dict)      # e.g., {"X-API-Key": "..."}
    cookies: Optional[CookieJar] = None               # session cookies


class CredentialStore:
    def __init__(self, config: ExecutorConfig):
        self.config = config
        self._identities: dict[str, IdentityContext] = {}
        for role, token in config.seed_tokens.items():
            ctx = IdentityContext()
            auth_header = config.auth_header_name or "Authorization"
            ctx.headers[auth_header] = f"Bearer {token}" if token else token
            self._identities[role] = ctx
        self._session_data: dict[str, Any] = {}

    def set_identity(self, role: str, ctx: IdentityContext) -> None:
        self._identities[role] = ctx

    def get_identity(self, role: str) -> Optional[IdentityContext]:
        if role == "anonymous":
            return IdentityContext()
        return self._identities.get(role)

    async def ensure_identity(self, role: str, client: httpx.AsyncClient) -> IdentityContext:
        if role == "anonymous":
            return IdentityContext()
        if ctx := self.get_identity(role):
            return ctx
        if self.config.allow_self_registration and self.config.registration_endpoint:
            try:
                ctx = await self._register_user(role, client)
                if ctx:
                    self.set_identity(role, ctx)
                    return ctx
            except Exception as e:
                print(f"[executor] Registration failed for {role}: {e}")
        return IdentityContext()

    async def _register_user(self, role: str, client: httpx.AsyncClient) -> Optional[IdentityContext]:
        reg_body = {
            "username": f"test_{role}_{hash(role) % 10000}",
            "password": "Test1234!",
            "role": role,
        }
        reg_url = urljoin(self.config.base_url, self.config.registration_endpoint)
        resp = await client.post(reg_url, json=reg_body)
        if resp.status_code == 201:
            login_url = urljoin(self.config.base_url, self.config.login_endpoint or "/login")
            login_body = {"username": reg_body["username"], "password": reg_body["password"]}
            resp2 = await client.post(login_url, json=login_body)
            if resp2.status_code == 200:
                data = resp2.json()
                token = data.get("access_token") or data.get("token")
                ctx = IdentityContext()
                if token:
                    auth_header = self.config.auth_header_name or "Authorization"
                    ctx.headers[auth_header] = f"Bearer {token}"
                if resp2.cookies:
                    ctx.cookies = copy.copy(resp2.cookies.jar)
                return ctx
        return None

    def store(self, key: str, data: Any) -> None:
        _json_path_set(self._session_data, key, data)

    def get(self, key: str) -> Optional[Any]:
        return _json_path_get(self._session_data, key)

    def get_all(self) -> dict:
        return dict(self._session_data)

    def clear_data(self) -> None:
        self._session_data.clear()


# ─── Request template ───────────────────────────────────────────────────────

@dataclass
class RequestTemplate:
    method: HTTPMethod
    url: str = ""
    url_template: str = ""
    url_vars: dict[str, str] = field(default_factory=dict)

    headers: dict = field(default_factory=dict)
    body: Any = None
    auth_role: Optional[str] = None
    send_cookies: bool = False

    store_response_as: Optional[str] = None

    extract_headers: dict[str, str] = field(default_factory=dict)
    extract_json_paths: dict[str, str] = field(default_factory=dict)

    # Assertions
    expected_status: Optional[int] = None
    status_range: tuple[int, int] = (200, 399)
    success_oracle: Optional[Callable[[httpx.Response], bool]] = None
    json_path_required: list[str] = field(default_factory=list)
    response_contains: Optional[str] = None
    response_absent: Optional[str] = None
    json_path_equals: Optional[dict[str, Any]] = None
    json_path_exists: Optional[list[str]] = None

    # Flow control
    is_setup: bool = False
    is_attack: bool = False
    skip_if: Optional[Callable[[dict], bool]] = None
    depends_on: Optional[str] = None

    # Safety
    is_destructive: bool = False

    def resolve_url(self, stored_data: dict) -> str:
        base = self.url_template or self.url
        for var_name, json_path in self.url_vars.items():
            val = _json_path_get(stored_data, json_path)
            if val is not None:
                base = base.replace(f"{{{var_name}}}", str(val))
        return base


@dataclass
class RollbackAction:
    method: HTTPMethod
    url_template: str
    url_vars: dict[str, str] = field(default_factory=dict)
    auth_role: str = "user"
    body: Any = None


@dataclass
class VerificationResult:
    hypothesis_id: str
    vuln_class: str
    endpoint_id: str
    status: VerificationStatus = VerificationStatus.INCONCLUSIVE
    impact: ImpactLevel = ImpactLevel.NONE
    evidence: list[str] = field(default_factory=list)
    request_log: list[dict] = field(default_factory=list)
    error: Optional[str] = None
    teardown_performed: bool = False
    cleanup_exceptions: list[str] = field(default_factory=list)


@dataclass
class ExecutorConfig:
    base_url: str
    seed_tokens: dict[str, str] = field(default_factory=dict)
    allow_self_registration: bool = False
    registration_endpoint: Optional[str] = None
    login_endpoint: Optional[str] = None
    allow_destructive_actions: bool = False
    max_impact: ImpactLevel = ImpactLevel.MEDIUM
    request_timeout: float = 30.0
    user_agent: str = "SecureGraph-Verifier/3.0"
    step_delay_ms: int = 750
    enable_teardown: bool = True
    auth_header_name: Optional[str] = None


# ─── Main Executor ──────────────────────────────────────────────────────────

class Executor:
    def __init__(self, config: ExecutorConfig, graph: StateGraph):
        self.config = config
        self.graph = graph
        self.creds = CredentialStore(config)
        self._client: Optional[httpx.AsyncClient] = None
        self._rollback_stack: list[RollbackAction] = []

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            base_url=self.config.base_url,
            timeout=self.config.request_timeout,
            headers={"User-Agent": self.config.user_agent},
            follow_redirects=False,
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    async def validate_hypothesis(self, hypothesis: AttackHypothesis) -> VerificationResult:
        if not self._client:
            raise RuntimeError("Executor must be used as async context manager")

        result = VerificationResult(
            hypothesis_id=hypothesis.endpoint_id,
            vuln_class=hypothesis.vuln_class,
            endpoint_id=hypothesis.endpoint_id,
            status=VerificationStatus.INCONCLUSIVE,
        )

        if self._impact_ceiling_exceeded(hypothesis.severity_estimate):
            result.error = "Impact exceeds safety ceiling"
            return result

        try:
            steps = await self._generate_steps(hypothesis)
        except Exception as e:
            result.error = f"Step generation failed: {e}"
            return result

        stored_data = dict(self.creds.get_all())
        request_log = []
        abort = False

        for i, step in enumerate(steps):
            if abort:
                break
            if i > 0 and self.config.step_delay_ms > 0:
                await asyncio.sleep(self.config.step_delay_ms / 1000.0)

            if step.skip_if and step.skip_if(stored_data):
                continue

            if step.depends_on and step.depends_on not in stored_data:
                result.error = f"Step {i} depends on '{step.depends_on}' but not available"
                abort = True
                break

            full_url = urljoin(self.config.base_url, step.resolve_url(stored_data))

            role = step.auth_role or "anonymous"
            identity = await self.creds.ensure_identity(role, self._client)
            headers = {**identity.headers, **step.headers}
            cookies = None
            if step.send_cookies and identity.cookies:
                cookies = identity.cookies

            try:
                resp = await self._client.request(
                    method=step.method.value.upper(),
                    url=full_url,
                    headers=headers,
                    cookies=cookies,
                    json=step.body if isinstance(step.body, dict) else None,
                    content=str(step.body) if isinstance(step.body, str) else None,
                )
            except Exception as e:
                result.error = f"Request {i} failed: {e}"
                abort = True
                break

            log_entry = {
                "step": i,
                "request": f"{step.method.value} {full_url}",
                "status": resp.status_code,
                "headers_sent": headers,
                "response_body": resp.text[:500],
            }
            request_log.append(log_entry)

            if step.store_response_as:
                try:
                    stored = resp.json()
                    log_entry["response_json"] = stored
                except Exception:
                    stored = resp.text
                _json_path_set(stored_data, step.store_response_as, stored)

            for header_name, store_path in step.extract_headers.items():
                value = resp.headers.get(header_name)
                if value:
                    _json_path_set(stored_data, store_path, value)
                    log_entry.setdefault("extracted_headers", {})[header_name] = value

            if resp.headers.get("content-type", "").startswith("application/json"):
                try:
                    js = resp.json()
                    for json_path, store_path in step.extract_json_paths.items():
                        val = _json_path_get(js, f"$.{json_path}")
                        if val is not None:
                            _json_path_set(stored_data, store_path, val)
                            log_entry.setdefault("extracted_json", {})[json_path] = val
                except Exception:
                    pass

            # Success oracle
            if step.success_oracle:
                step_ok = step.success_oracle(resp)
            else:
                step_ok = self._default_success_oracle(resp, step)

            if step.expected_status is not None and resp.status_code != step.expected_status:
                step_ok = False
                result.evidence.append(f"Expected status {step.expected_status}, got {resp.status_code}")
            elif not (step.status_range[0] <= resp.status_code <= step.status_range[1]):
                step_ok = False
                result.evidence.append(f"Status {resp.status_code} outside range {step.status_range}")

            if step.response_contains and step.response_contains not in resp.text:
                step_ok = False
            if step.response_absent and step.response_absent in resp.text:
                step_ok = False
            if step.json_path_equals:
                js = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                for path, expected in step.json_path_equals.items():
                    actual = _json_path_get(js, path)
                    if actual != expected:
                        step_ok = False
                        result.evidence.append(f"JSON path {path}: expected {expected}, got {actual}")
            if step.json_path_exists:
                js = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                for path in step.json_path_exists:
                    if _json_path_get(js, path) is None:
                        step_ok = False
                        result.evidence.append(f"JSON path {path} missing")

            if step.is_destructive and self.config.allow_destructive_actions and self.config.enable_teardown:
                self._schedule_rollback(step, stored_data, role)

            if step.is_setup and not step_ok:
                result.error = f"Setup step {i} failed (status {resp.status_code})"
                result.evidence.append(f"Setup failure at step {i}")
                abort = True
                continue

            if (step.is_attack or not step.is_setup) and not step_ok:
                result.status = VerificationStatus.DISPROVED
                result.evidence.append(f"Attack/verification step {i} failed")
                abort = True
                continue

        if self.config.enable_teardown and self._rollback_stack:
            cleanup_errors = await self._perform_teardown()
            result.teardown_performed = True
            result.cleanup_exceptions = cleanup_errors

        result.request_log = request_log

        if not abort and not result.error and result.status != VerificationStatus.DISPROVED:
            result.status = VerificationStatus.VERIFIED
            result.evidence.insert(0, f"Vulnerability {hypothesis.vuln_class} confirmed on {hypothesis.endpoint_id}")

        result.impact = self._estimate_impact(hypothesis, result.status == VerificationStatus.VERIFIED)
        if result.status == VerificationStatus.VERIFIED:
            self._feed_back(hypothesis, result)

        return result

    def _default_success_oracle(self, resp: httpx.Response, step: RequestTemplate) -> bool:
        """Success = 2xx, no blacklisted keywords, mandatory JSON paths present."""
        if not (200 <= resp.status_code <= 299):
            return False

        # Null‑safe body extraction
        body_text = resp.text if resp.text is not None else ""
        body_lower = body_text.lower()
        if any(kw in body_lower for kw in _DEFAULT_ORACLE_BLACKLIST):
            return False

        if step.json_path_required:
            try:
                js = resp.json()
            except Exception:
                return False
            for path in step.json_path_required:
                value = _json_path_get(js, path)
                if value is None or value == "" or value is False:
                    return False
                if isinstance(value, bool) and not value:
                    return False
                if not value:
                    return False
        return True

    async def _generate_steps(self, hypothesis: AttackHypothesis) -> list[RequestTemplate]:
        method_map = {
            "IDOR": self._gen_idor_steps,
            "MissingAuthentication": self._gen_missing_auth_steps,
            "AuthBypassPathAsymmetry": self._gen_path_asymmetry_steps,
            "MassAssignment": self._gen_mass_assignment_steps,
            "UnauthenticatedWrite": self._gen_unauthenticated_write_steps,
            "DataLeakIDOR": self._gen_idor_steps,
        }
        gen = method_map.get(hypothesis.vuln_class)
        if not gen:
            raise ValueError(f"No step generator for vuln class '{hypothesis.vuln_class}'")
        return await gen(hypothesis)

    async def _gen_idor_steps(self, hyp: AttackHypothesis) -> list[RequestTemplate]:
        ep = self.graph.get_node(hyp.endpoint_id)
        if not isinstance(ep, EndpointNode):
            raise ValueError("IDOR endpoint not found")

        is_write = ep.method in (HTTPMethod.PUT, HTTPMethod.PATCH, HTTPMethod.DELETE, HTTPMethod.POST)
        id_param = None
        for nid in hyp.chain:
            node = self.graph.get_node(nid)
            if isinstance(node, ParameterNode) and node.location in (ParamLocation.PATH, ParamLocation.QUERY):
                id_param = node
                break
        param_name = id_param.label if id_param else "id"

        legit_role = "user"
        for ac in ep.auth_contexts:
            if ac.role not in ("anonymous", "attacker"):
                legit_role = ac.role
                break
        attacker_role = "attacker" if "attacker" in self.creds._identities else "anonymous"

        create_ep_id = self._infer_create_endpoint(ep)
        steps = []

        if create_ep_id and is_write:
            create_ep = self.graph.get_node(create_ep_id)
            if isinstance(create_ep, EndpointNode):
                steps.append(RequestTemplate(
                    method=create_ep.method,
                    url=create_ep.path,
                    body=self._generate_creation_body(create_ep),
                    auth_role=legit_role,
                    send_cookies=True,
                    is_setup=True,
                    store_response_as="setup_1.created_resource",
                    extract_headers={"Location": "setup_1.resource_location"},
                    extract_json_paths={"id": "setup_1.resource_id"},
                    json_path_required=["id"],
                    is_destructive=True,
                ))
                steps.append(RequestTemplate(
                    method=ep.method,
                    url_template=ep.path,
                    url_vars={param_name: "setup_1.resource_id"},
                    auth_role=attacker_role,
                    send_cookies=True,
                    is_attack=True,
                    status_range=(200, 299),
                    is_destructive=True,
                ))
                steps.append(RequestTemplate(
                    method=HTTPMethod.GET,
                    url_template=ep.path,
                    url_vars={param_name: "setup_1.resource_id"},
                    auth_role=legit_role,
                    send_cookies=True,
                    is_attack=False,
                    store_response_as="post_attack_state",
                    json_path_required=["id"],
                ))
        else:
            if create_ep_id:
                create_ep = self.graph.get_node(create_ep_id)
                if isinstance(create_ep, EndpointNode):
                    steps.append(RequestTemplate(
                        method=create_ep.method,
                        url=create_ep.path,
                        body=self._generate_creation_body(create_ep),
                        auth_role=legit_role,
                        send_cookies=True,
                        is_setup=True,
                        store_response_as="setup_1.created_resource",
                        extract_headers={"Location": "setup_1.resource_location"},
                        extract_json_paths={"id": "setup_1.resource_id"},
                        json_path_required=["id"],
                        is_destructive=True,
                    ))
            steps.append(RequestTemplate(
                method=ep.method,
                url_template=ep.path,
                url_vars={param_name: "setup_1.resource_id"},
                auth_role=attacker_role,
                send_cookies=True,
                is_attack=True,
                store_response_as="attack_data",
                json_path_required=["$"],
            ))
        return steps

    async def _gen_missing_auth_steps(self, hyp: AttackHypothesis) -> list[RequestTemplate]:
        ep = self.graph.get_node(hyp.endpoint_id)
        if not isinstance(ep, EndpointNode):
            raise ValueError("Endpoint not found")
        return [
            RequestTemplate(
                method=ep.method,
                url=ep.path,
                auth_role="anonymous",
                send_cookies=False,
                is_attack=True,
                status_range=(200, 299),
                is_destructive=ep.method in (HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.PATCH, HTTPMethod.DELETE),
            )
        ]

    async def _gen_path_asymmetry_steps(self, hyp: AttackHypothesis) -> list[RequestTemplate]:
        ep = self.graph.get_node(hyp.endpoint_id)
        if not isinstance(ep, EndpointNode):
            raise ValueError("Endpoint not found")
        return [
            RequestTemplate(
                method=ep.method,
                url=ep.path,
                auth_role="anonymous",
                send_cookies=False,
                is_attack=True,
                status_range=(200, 299),
                is_destructive=ep.method in (HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.PATCH, HTTPMethod.DELETE),
            )
        ]

    async def _gen_mass_assignment_steps(self, hyp: AttackHypothesis) -> list[RequestTemplate]:
        ep = self.graph.get_node(hyp.endpoint_id)
        if not isinstance(ep, EndpointNode):
            raise ValueError("Endpoint not found")

        ownership_field = "owner_id"
        model_name = None
        for nid in hyp.chain:
            node = self.graph.get_node(nid)
            if isinstance(node, ParameterNode) and node.python_type in self.graph._pydantic_models_by_name():
                model_name = node.python_type
                break
        if model_name:
            model_node = self.graph.get_node(self.graph._pydantic_models_by_name()[model_name])
            if isinstance(model_node, ModelNode) and model_node.ownership_fields:
                ownership_field = model_node.ownership_fields[0]

        body = self._generate_creation_body(ep, model_name=model_name)
        attacker_id = "attacker_owned_99"
        body[ownership_field] = attacker_id

        steps = [
            RequestTemplate(
                method=ep.method,
                url=ep.path,
                body=body,
                auth_role="user",
                send_cookies=True,
                is_setup=False,
                is_attack=True,
                store_response_as="mass_assignment_result",
                extract_headers={"Location": "mass_assignment_result.location"},
                extract_json_paths={"id": "mass_assignment_result.id"},
                json_path_required=["id"],
                is_destructive=True,
            ),
            RequestTemplate(
                method=HTTPMethod.GET,
                url_template="",
                url_vars={"_": "mass_assignment_result.location"},
                skip_if=lambda data: "mass_assignment_result.location" not in data,
                auth_role="user",
                send_cookies=True,
                is_attack=False,
                json_path_equals={f"$.{ownership_field}": attacker_id},
                json_path_required=["$.id"],
            ),
        ]
        return steps

    async def _gen_unauthenticated_write_steps(self, hyp: AttackHypothesis) -> list[RequestTemplate]:
        ep = self.graph.get_node(hyp.endpoint_id)
        if not isinstance(ep, EndpointNode):
            raise ValueError("Endpoint not found")
        return [
            RequestTemplate(
                method=ep.method,
                url=ep.path,
                auth_role="anonymous",
                send_cookies=False,
                body=self._generate_creation_body(ep),
                status_range=(200, 299),
                is_attack=True,
                is_destructive=True,
            )
        ]

    # ── Payload generation (recursive, depth‑guarded, smart dummies) ────────

    def _generate_creation_body(self, ep: EndpointNode, model_name: Optional[str] = None) -> dict:
        body = {}
        if model_name and model_name in self.graph._pydantic_models_by_name():
            model_node = self.graph.get_node(self.graph._pydantic_models_by_name()[model_name])
            if isinstance(model_node, ModelNode):
                return self._build_model_dict(model_node)
        for edge in self.graph.incoming(ep.id):
            if edge.type != EdgeType.PARAM_FLOWS_TO:
                continue
            param = self.graph.get_node(edge.src)
            if isinstance(param, ParameterNode) and param.location == ParamLocation.BODY:
                if any(k in param.label.lower() for k in ["owner", "user_id", "tenant", "created_by"]):
                    continue
                body[param.label] = self._dummy_value_for_type(param.python_type)
        return body

    def _build_model_dict(self, model_node: ModelNode, depth: int = 0) -> dict:
        """Recursively build a dict, respecting MAX_NESTING_DEPTH."""
        if depth > MAX_NESTING_DEPTH:
            return {}
        body = {}
        for field_id in model_node.fields:
            fnode = self.graph.get_node(field_id)
            if isinstance(fnode, ModelFieldNode):
                if fnode.is_ownership_marker and depth == 0:
                    continue
                body[fnode.label] = self._dummy_value_for_type(fnode.field_type, depth + 1)
        return body

    def _dummy_value_for_type(self, python_type: str, depth: int = 0) -> Any:
        t = python_type.lower().replace(" ", "")
        if t in self.graph._pydantic_models_by_name():
            model_node = self.graph.get_node(self.graph._pydantic_models_by_name()[t])
            if isinstance(model_node, ModelNode):
                return self._build_model_dict(model_node, depth)
        if t in ("str", "string"):
            return "test_string"
        elif t in ("int", "integer"):
            return 42
        elif t in ("float", "number"):
            return 3.14
        elif t in ("bool", "boolean"):
            return True
        elif t == "uuid":
            return str(uuid.uuid4())
        elif "email" in t or (t == "str" and self._has_format_hint(t, "email")):
            return "test@example.com"
        elif "date" in t:
            return "2025-01-01"
        elif "datetime" in t:
            return "2025-01-01T00:00:00Z"
        elif "url" in t:
            return "https://example.com"
        elif "uri" in t:
            return "https://example.com"
        elif t.startswith("list"):
            return []
        elif t.startswith("dict"):
            return {}
        return "test"

    def _has_format_hint(self, field_type: str, hint: str) -> bool:
        return False  # can be expanded when graph metadata includes format hints

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _infer_create_endpoint(self, ep: EndpointNode) -> Optional[str]:
        base = re.sub(r"/\{[^}]+\}$", "", ep.path)
        for e in self.graph.endpoints():
            if e.path == base and e.method == HTTPMethod.POST:
                return e.id
        return None

    def _schedule_rollback(self, step: RequestTemplate, stored_data: dict, role: str) -> None:
        resource_url = None
        resource_id = None
        if "setup_1.resource_location" in stored_data:
            resource_url = stored_data["setup_1.resource_location"]
        elif "mass_assignment_result.location" in stored_data:
            resource_url = stored_data["mass_assignment_result.location"]
        elif "setup_1.resource_id" in stored_data:
            resource_id = stored_data["setup_1.resource_id"]
            if step.url:
                base = step.url.split("?")[0].rstrip("/")
                resource_url = f"{base}/{resource_id}"
        if resource_url:
            self._rollback_stack.append(RollbackAction(
                method=HTTPMethod.DELETE,
                url_template=resource_url,
                auth_role=role,
            ))

    async def _perform_teardown(self) -> list[str]:
        errors = []
        if not self._client:
            return errors
        for action in reversed(self._rollback_stack):
            try:
                identity = await self.creds.ensure_identity(action.auth_role, self._client)
                headers = identity.headers
                full_url = urljoin(self.config.base_url, action.url_template)
                resp = await self._client.delete(full_url, headers=headers)
                if resp.status_code >= 400:
                    errors.append(f"Teardown DELETE {full_url} returned {resp.status_code}: {resp.text[:100]}")
            except Exception as e:
                errors.append(f"Teardown DELETE {action.url_template} failed: {e}")
        self._rollback_stack.clear()
        return errors

    def _estimate_impact(self, hyp: AttackHypothesis, verified: bool) -> ImpactLevel:
        if not verified:
            return ImpactLevel.NONE
        sev = hyp.severity_estimate.lower()
        if "critical" in sev:
            return ImpactLevel.CRITICAL
        elif "high" in sev:
            return ImpactLevel.HIGH
        elif "medium" in sev:
            return ImpactLevel.MEDIUM
        return ImpactLevel.LOW

    def _impact_ceiling_exceeded(self, severity: str) -> bool:
        order = {ImpactLevel.NONE: 0, ImpactLevel.LOW: 1, ImpactLevel.MEDIUM: 2, ImpactLevel.HIGH: 3, ImpactLevel.CRITICAL: 4}
        sev_lvl = ImpactLevel(severity.lower()) if severity.lower() in ImpactLevel.__members__ else ImpactLevel.MEDIUM
        return order[sev_lvl] > order[self.config.max_impact]

    def _feed_back(self, hyp: AttackHypothesis, result: VerificationResult) -> None:
        hyp.llm_score = 1.0 if result.status == VerificationStatus.VERIFIED else 0.0
