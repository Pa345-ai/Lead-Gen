# extractors/fastapi_extractor.py
"""
FastAPI AST Extractor – with ownership check parsing and response model linking.

Changes for IDOR:
- Extract `response_model=` from route decorators and add RESPONSE_SHAPE edges.
- Parse function return type annotations (-> UserResponse) to discover response models.
- Mark model fields with ownership patterns as `is_ownership_marker=True`.
- Populate ModelNode.ownership_fields list.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import Optional

import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Node as TSNode

from core.graph import (
    StateGraph, EndpointNode, ParameterNode, ModelNode, ModelFieldNode,
    PermissionNode, ExternalCallNode, Edge,
    NodeType, EdgeType, HTTPMethod, ParamLocation, AuthContext,
)


# ─── Setup ───────────────────────────────────────────────────────────────────

PY_LANGUAGE = Language(tspython.language())
_parser = Parser(PY_LANGUAGE)

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}

_AUTH_DEP_PATTERNS = [
    re.compile(r"get_current[\w_]*user", re.I),
    re.compile(r"require[\w_]*(auth|admin|role|permission|scope)", re.I),
    re.compile(r"verify[\w_]*(token|jwt|api_key)", re.I),
    re.compile(r"oauth2[\w_]*", re.I),
    re.compile(r"http[\w_]*bearer", re.I),
    re.compile(r"api[\w_]*key[\w_]*", re.I),
    re.compile(r"authenticate", re.I),
    re.compile(r"authorize", re.I),
]

# Ownership field patterns (trigger IDOR / MassAssignment)
_OWNERSHIP_FIELD_PATTERNS = [
    re.compile(r"(owner|user)_?id$", re.I),
    re.compile(r"created_?by$", re.I),
    re.compile(r"tenant_?id$", re.I),
    re.compile(r"account_?id$", re.I),
    re.compile(r"^sub$", re.I),
    re.compile(r"author_?id$", re.I),
]

_SQL_PATTERNS = [
    re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b", re.I),
]


def _is_ownership_field(name: str) -> bool:
    return any(p.search(name) for p in _OWNERSHIP_FIELD_PATTERNS)


def _is_auth_dep(name: str) -> bool:
    return any(p.search(name) for p in _AUTH_DEP_PATTERNS)


def _text(node: TSNode, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _infer_role(dep_name: str) -> str:
    n = dep_name.lower()
    if "admin" in n:
        return "admin"
    if "service" in n or "internal" in n:
        return "service"
    if "anonymous" in n or "public" in n:
        return "anonymous"
    return "user"


# ─── Main Extractor ──────────────────────────────────────────────────────────

class FastAPIExtractor:
    def __init__(self, graph: StateGraph):
        self.graph = graph
        self._pydantic_models: dict[str, str] = {}   # class name → node id
        self._dep_functions: dict[str, str] = {}     # fn name → permission node id

    def process_file(self, filepath: str) -> None:
        src_path = Path(filepath)
        src_bytes = src_path.read_bytes()
        tree = _parser.parse(src_bytes)
        self._walk_module(tree.root_node, src_bytes, str(src_path))

    def process_source(self, source: str, label: str = "<string>") -> None:
        src_bytes = source.encode("utf-8")
        tree = _parser.parse(src_bytes)
        self._walk_module(tree.root_node, src_bytes, label)

    def _walk_module(self, root: TSNode, src: bytes, filepath: str) -> None:
        for child in root.children:
            if child.type == "class_definition":
                self._extract_class(child, src, filepath)
            elif child.type == "decorated_definition":
                self._extract_decorated(child, src, filepath)
            elif child.type == "function_definition":
                self._maybe_extract_dep_function(child, src, filepath)

    # ── Pydantic model extraction (with ownership marking) ─────────────────────
    def _extract_class(self, node: TSNode, src: bytes, filepath: str) -> None:
        name_node = node.child_by_field_name("name")
        if not name_node:
            return
        class_name = _text(name_node, src)

        args_node = node.child_by_field_name("superclasses")
        if not args_node:
            return
        bases_text = _text(args_node, src)
        if "BaseModel" not in bases_text and "Schema" not in bases_text:
            return

        model_id = f"model:{class_name}"
        ownership_fields = []
        field_ids = []

        body = node.child_by_field_name("body")
        if body:
            for stmt in body.children:
                # Annotated assignment: name: Type = default
                if stmt.type in ("expression_statement",):
                    for expr in stmt.children:
                        if expr.type == "assignment":
                            fname, ftype = self._extract_annotated_assignment(expr, src)
                            if fname:
                                is_own = _is_ownership_field(fname)
                                if is_own:
                                    ownership_fields.append(fname)
                                field_id = f"field:{class_name}.{fname}"
                                fnode = ModelFieldNode(
                                    id=field_id,
                                    label=f"{class_name}.{fname}",
                                    file=filepath,
                                    line=expr.start_point[0] + 1,
                                    field_type=ftype,
                                    parent_model=model_id,
                                    is_ownership_marker=is_own,
                                )
                                self.graph.add_node(fnode)
                                field_ids.append(field_id)
                elif stmt.type == "annotated_assignment":
                    fname, ftype = self._extract_annotated_assignment(stmt, src)
                    if fname:
                        is_own = _is_ownership_field(fname)
                        if is_own:
                            ownership_fields.append(fname)
                        field_id = f"field:{class_name}.{fname}"
                        fnode = ModelFieldNode(
                            id=field_id,
                            label=f"{class_name}.{fname}",
                            file=filepath,
                            line=stmt.start_point[0] + 1,
                            field_type=ftype,
                            parent_model=model_id,
                            is_ownership_marker=is_own,
                        )
                        self.graph.add_node(fnode)
                        field_ids.append(field_id)

        model_node = ModelNode(
            id=model_id,
            label=class_name,
            file=filepath,
            line=node.start_point[0] + 1,
            fields=field_ids,
            ownership_fields=ownership_fields,
        )
        self.graph.add_node(model_node)
        self._pydantic_models[class_name] = model_id

        for fid in field_ids:
            self.graph.add_edge(Edge(src=fid, dst=model_id, type=EdgeType.FIELD_OF))

    def _extract_annotated_assignment(self, node: TSNode, src: bytes) -> tuple[str, str]:
        name_node = node.child_by_field_name("left") or node.child_by_field_name("name")
        type_node = node.child_by_field_name("type") or node.child_by_field_name("annotation")
        if not name_node:
            return "", "Any"
        fname = _text(name_node, src).strip()
        ftype = _text(type_node, src).strip() if type_node else "Any"
        return fname, ftype

    # ── Route extraction with RESPONSE_SHAPE linking ─────────────────────────
    def _extract_decorated(self, node: TSNode, src: bytes, filepath: str) -> None:
        decorators = []
        inner = None
        for child in node.children:
            if child.type == "decorator":
                decorators.append(child)
            elif child.type == "function_definition":
                inner = child

        if not inner:
            return

        for dec in decorators:
            endpoint = self._try_extract_route_decorator(dec, src, filepath, inner)
            if endpoint:
                return

        self._maybe_extract_dep_function(inner, src, filepath)

    def _try_extract_route_decorator(
        self, dec: TSNode, src: bytes, filepath: str, fn_node: TSNode
    ) -> Optional[EndpointNode]:
        dec_text = _text(dec, src)
        method = None
        path = None

        for m in _HTTP_METHODS:
            if re.search(rf"\.{m}\s*\(", dec_text, re.I):
                method = HTTPMethod(m.upper())
                break

        if method is None:
            if "api_route" in dec_text:
                method = HTTPMethod.ANY
            else:
                return None

        path_match = re.search(r'["\']([/][^"\']*)["\']', dec_text)
        path = path_match.group(1) if path_match else "/"

        fn_name_node = fn_node.child_by_field_name("name")
        fn_name = _text(fn_name_node, src) if fn_name_node else "unknown"
        line = fn_node.start_point[0] + 1

        endpoint_id = f"endpoint:{path}:{method.value}"
        if self.graph.get_node(endpoint_id):
            endpoint_id = f"endpoint:{path}:{method.value}:{filepath}"

        params, auth_contexts, auth_required = self._extract_function_params(
            fn_node, src, filepath, endpoint_id
        )

        # NEW: Extract response model from decorator or return annotation
        response_model_id = self._extract_response_model(dec_text, fn_node, src)
        if response_model_id:
            # Add RESPONSE_SHAPE edge from endpoint to model
            self.graph.add_edge(Edge(
                src=endpoint_id,
                dst=response_model_id,
                type=EdgeType.RESPONSE_SHAPE,
                auth_contexts=auth_contexts,
            ))

        body_node = fn_node.child_by_field_name("body")
        if body_node:
            body_contexts = self._scan_body_for_ownership_check(body_node, src, endpoint_id)
            auth_contexts.extend(body_contexts)
            if body_contexts and not auth_required:
                auth_required = True

        endpoint = EndpointNode(
            id=endpoint_id,
            label=f"{method.value} {path}",
            file=filepath,
            line=line,
            method=method,
            path=path,
            function_name=fn_name,
            auth_contexts=auth_contexts,
            auth_required=auth_required,
            metadata={"decorator": dec_text.strip()},
        )
        self.graph.add_node(endpoint)

        for param in params:
            self.graph.add_node(param)
            self.graph.add_edge(Edge(
                src=param.id,
                dst=endpoint_id,
                type=EdgeType.PARAM_FLOWS_TO,
                auth_contexts=auth_contexts,
            ))

        for ac in auth_contexts:
            if ac.source.startswith("body_ownership_check"):
                continue
            perm_id = f"perm:{ac.source}"
            if not self.graph.get_node(perm_id):
                pnode = PermissionNode(
                    id=perm_id,
                    label=ac.source,
                    dependency_fn=ac.source,
                    inferred_role=ac.role,
                )
                self.graph.add_node(pnode)
                self._dep_functions[ac.source] = perm_id
            self.graph.add_edge(Edge(
                src=endpoint_id,
                dst=perm_id,
                type=EdgeType.ENDPOINT_REQUIRES,
                auth_contexts=[ac],
            ))

        if body_node:
            self._extract_external_calls(body_node, src, filepath, endpoint_id, auth_contexts)

        return endpoint

    def _extract_response_model(self, dec_text: str, fn_node: TSNode, src: bytes) -> Optional[str]:
        """
        Extract response model from either:
          - decorator: `@router.get(..., response_model=UserResponse)`
          - return type annotation: `def ... -> UserResponse:`
        Returns model node ID if found, else None.
        """
        # From decorator
        match = re.search(r"response_model\s*=\s*([\w.]+)", dec_text)
        if match:
            model_name = match.group(1).split(".")[-1]
            if model_name in self._pydantic_models:
                return self._pydantic_models[model_name]

        # From return type annotation
        ret_type_node = fn_node.child_by_field_name("return_type")
        if ret_type_node:
            ret_text = _text(ret_type_node, src).strip()
            # Strip Optional[ ... ] or Union[ ... ]
            ret_text = re.sub(r"Optional\[(.*)\]", r"\1", ret_text)
            ret_text = re.sub(r"Union\[([^,]+),.*\]", r"\1", ret_text)
            model_name = ret_text.split("[")[0].split(".")[-1]
            if model_name in self._pydantic_models:
                return self._pydantic_models[model_name]

        return None

    def _scan_body_for_ownership_check(self, body_node: TSNode, src: bytes, endpoint_id: str) -> list[AuthContext]:
        body_text = _text(body_node, src)
        contexts = []
        patterns = [
            (r"if\s+(\w+)\.(user_id|owner_id|created_by)\s*!=\s*current_user\.id", "owner_id_mismatch_deny"),
            (r"if\s+(\w+)\.(user_id|owner_id|created_by)\s*==\s*current_user\.id", "owner_id_match_grant"),
            (r"if\s+current_user\.id\s*!=\s*(\w+)\.(user_id|owner_id)", "owner_id_mismatch_deny"),
            (r"if\s+(\w+)\.(user_id|owner_id)\s*!=\s*current_user_id", "owner_id_mismatch_deny"),
            (r"if\s+(\w+)\.user_id\s*!=\s*current_user\.\w+_id", "owner_id_mismatch_deny"),
        ]
        for pattern, constraint in patterns:
            if re.search(pattern, body_text, re.IGNORECASE):
                ac = AuthContext(
                    role="user",
                    constraint=constraint,
                    source="body_ownership_check",
                    confidence=0.95,
                )
                contexts.append(ac)
                break
        return contexts

    def _extract_function_params(
        self, fn_node: TSNode, src: bytes, filepath: str, endpoint_id: str
    ) -> tuple[list[ParameterNode], list[AuthContext], bool]:
        params: list[ParameterNode] = []
        auth_contexts: list[AuthContext] = []
        auth_required = False

        params_node = fn_node.child_by_field_name("parameters")
        if not params_node:
            return params, auth_contexts, auth_required

        fn_name_node = fn_node.child_by_field_name("name")
        fn_name = _text(fn_name_node, src) if fn_name_node else "fn"

        for param in params_node.named_children:
            if param.type not in ("identifier", "typed_parameter", "typed_default_parameter", "default_parameter"):
                continue

            param_text = _text(param, src)

            if re.match(r"^(self|cls|request|response|background_tasks|db)\b", param_text):
                continue

            if "Depends(" in param_text:
                dep_name = self._extract_depends_name(param_text)
                if dep_name:
                    is_auth = _is_auth_dep(dep_name)
                    if is_auth:
                        auth_required = True
                        role = _infer_role(dep_name)
                        ac = AuthContext(role=role, constraint=None, source=dep_name, confidence=0.85)
                        auth_contexts.append(ac)
                    elif any(k in dep_name.lower() for k in ["session", "db", "conn"]):
                        pass
                    else:
                        ac = AuthContext(role="unknown", constraint=None, source=dep_name, confidence=0.4)
                        auth_contexts.append(ac)
                continue

            if "Security(" in param_text:
                auth_required = True
                auth_contexts.append(AuthContext(role="user", constraint=None, source="Security", confidence=0.9))
                continue

            name, ptype, default, location = self._classify_param(param, src, fn_name)
            if not name:
                continue

            pnode = ParameterNode(
                id=f"param:{endpoint_id}:{name}",
                label=name,
                file=filepath,
                line=param.start_point[0] + 1,
                location=location,
                python_type=ptype,
                required=(default is None),
                default=default,
                user_controlled=True,
            )
            params.append(pnode)

        if not auth_required:
            sig_text = _text(params_node, src)
            if re.search(r"current_user|current_account", sig_text, re.I):
                auth_required = True
                auth_contexts.append(AuthContext(role="user", constraint=None, source="current_user_param", confidence=0.7))

        return params, auth_contexts, auth_required

    def _extract_depends_name(self, param_text: str) -> str:
        m = re.search(r"Depends\(\s*([\w_]+)", param_text)
        return m.group(1) if m else ""

    def _classify_param(self, param: TSNode, src: bytes, fn_name: str) -> tuple[str, str, Optional[str], ParamLocation]:
        param_text = _text(param, src)
        name_match = re.match(r"(\w+)", param_text)
        name = name_match.group(1) if name_match else ""
        if not name:
            return "", "Any", None, ParamLocation.QUERY

        type_str = "Any"
        type_node = param.child_by_field_name("type")
        if type_node:
            type_str = _text(type_node, src).strip()

        default = None
        default_node = param.child_by_field_name("value")
        if default_node:
            default = _text(default_node, src).strip()

        location = ParamLocation.QUERY
        if default:
            if re.search(r"\bPath\s*\(", default):
                location = ParamLocation.PATH
            elif re.search(r"\bQuery\s*\(", default):
                location = ParamLocation.QUERY
            elif re.search(r"\bBody\s*\(", default):
                location = ParamLocation.BODY
            elif re.search(r"\bHeader\s*\(", default):
                location = ParamLocation.HEADER
            elif re.search(r"\bCookie\s*\(", default):
                location = ParamLocation.COOKIE
            elif re.search(r"\bForm\s*\(", default):
                location = ParamLocation.BODY

        if type_str in self._pydantic_models:
            location = ParamLocation.BODY

        return name, type_str, default, location

    def _extract_external_calls(
        self, body: TSNode, src: bytes, filepath: str,
        endpoint_id: str, auth_contexts: list[AuthContext]
    ) -> None:
        body_text = _text(body, src)
        for pat in _SQL_PATTERNS:
            if pat.search(body_text):
                for i, line in enumerate(body_text.splitlines()):
                    if pat.search(line):
                        call_id = f"ext:{endpoint_id}:sql:{i}"
                        ext = ExternalCallNode(
                            id=call_id,
                            label=f"SQL in {endpoint_id.split(':')[1]}",
                            file=filepath,
                            line=body.start_point[0] + i + 1,
                            call_type="db",
                            query_fragment=line.strip()[:120],
                        )
                        self.graph.add_node(ext)
                        self.graph.add_edge(Edge(
                            src=endpoint_id,
                            dst=call_id,
                            type=EdgeType.CALLS,
                            auth_contexts=auth_contexts,
                        ))
                        break

        orm_patterns = [
            (r"\.query\(", "db"), (r"\.filter\(", "db"), (r"\.get\(", "db"),
            (r"await\s+\w+\.find", "db"), (r"session\.", "db"),
            (r"httpx\.|requests\.|aiohttp\.", "http"),
        ]
        for pat, call_type in orm_patterns:
            if re.search(pat, body_text):
                call_id = f"ext:{endpoint_id}:{call_type}:{pat[:10].strip()}"
                if not self.graph.get_node(call_id):
                    ext = ExternalCallNode(
                        id=call_id, label=f"{call_type.upper()} call in {endpoint_id}",
                        file=filepath, call_type=call_type,
                    )
                    self.graph.add_node(ext)
                    self.graph.add_edge(Edge(
                        src=endpoint_id, dst=call_id, type=EdgeType.CALLS,
                        auth_contexts=auth_contexts,
                    ))

    def _maybe_extract_dep_function(self, fn_node: TSNode, src: bytes, filepath: str) -> None:
        fn_name_node = fn_node.child_by_field_name("name")
        if not fn_name_node:
            return
        fn_name = _text(fn_name_node, src)
        if not _is_auth_dep(fn_name):
            return

        perm_id = f"perm:{fn_name}"
        if self.graph.get_node(perm_id):
            return

        role = _infer_role(fn_name)
        pnode = PermissionNode(
            id=perm_id, label=fn_name, file=filepath, line=fn_node.start_point[0] + 1,
            dependency_fn=fn_name, inferred_role=role,
        )
        self.graph.add_node(pnode)
        self._dep_functions[fn_name] = perm_id

    def enrich_path_params(self) -> None:
        for ep in self.graph.endpoints():
            path_vars = re.findall(r"\{(\w+)\}", ep.path)
            for var in path_vars:
                param_id = f"param:{ep.id}:{var}"
                existing = self.graph.get_node(param_id)
                if not existing:
                    pnode = ParameterNode(
                        id=param_id, label=var, file=ep.file, location=ParamLocation.PATH,
                        python_type="str", required=True, user_controlled=True,
                        metadata={"inferred_from_path_template": True},
                    )
                    self.graph.add_node(pnode)
                    self.graph.add_edge(Edge(
                        src=param_id, dst=ep.id, type=EdgeType.PARAM_FLOWS_TO,
                        auth_contexts=ep.auth_contexts,
                    ))
                else:
                    if isinstance(existing, ParameterNode):
                        existing.location = ParamLocation.PATH