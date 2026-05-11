"""
FastAPI AST Extractor

Uses tree-sitter to walk Python source files and extract:
  - Route definitions (@app.get, @router.post, etc.)
  - Function parameters (Path, Query, Body, Header, Cookie, Depends)
  - Pydantic model definitions and their fields
  - Auth dependency chains (Depends(get_current_user), OAuth2, HTTPBearer)
  - SQLAlchemy / raw SQL external call fragments

Populates a StateGraph directly. Does NOT do heuristic guessing — only
emits what is structurally present in the AST. Confidence is explicit.
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

# HTTP method decorators recognised
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}

# FastAPI dependency function names that imply authentication
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

# Fields that look like ownership markers
_OWNERSHIP_FIELD_PATTERNS = [
    re.compile(r"(owner|user)_?id$", re.I),
    re.compile(r"created_?by$", re.I),
    re.compile(r"tenant_?id$", re.I),
    re.compile(r"account_?id$", re.I),
    re.compile(r"^sub$", re.I),
    re.compile(r"author_?id$", re.I),
]

# SQL sinks
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
    """
    Parse one or more Python files and populate a StateGraph.

    Usage:
        graph = StateGraph()
        extractor = FastAPIExtractor(graph)
        extractor.process_file("app/routes/orders.py")
        extractor.process_file("app/models/order.py")
    """

    def __init__(self, graph: StateGraph):
        self.graph = graph
        # Track pydantic models seen so we can cross-reference
        self._pydantic_models: dict[str, str] = {}   # class name → node id
        # Track dependency functions seen (for multi-file resolution)
        self._dep_functions: dict[str, str] = {}     # fn name → permission node id

    def process_file(self, filepath: str) -> None:
        src_path = Path(filepath)
        src_bytes = src_path.read_bytes()
        tree = _parser.parse(src_bytes)
        self._walk_module(tree.root_node, src_bytes, str(src_path))

    def process_source(self, source: str, label: str = "<string>") -> None:
        """Parse raw source string — useful for testing."""
        src_bytes = source.encode("utf-8")
        tree = _parser.parse(src_bytes)
        self._walk_module(tree.root_node, src_bytes, label)

    # ── Module-level walk ─────────────────────────────────────────────────────

    def _walk_module(self, root: TSNode, src: bytes, filepath: str) -> None:
        """Top-level: collect class defs (models) and function defs (routes)."""
        for child in root.children:
            if child.type == "class_definition":
                self._extract_class(child, src, filepath)
            elif child.type == "decorated_definition":
                self._extract_decorated(child, src, filepath)
            elif child.type == "function_definition":
                # Undecorated functions may be dependency providers
                self._maybe_extract_dep_function(child, src, filepath)

    # ── Pydantic model extraction ─────────────────────────────────────────────

    def _extract_class(self, node: TSNode, src: bytes, filepath: str) -> None:
        """
        Extract Pydantic BaseModel subclasses.
        Recognises: class Foo(BaseModel), class Foo(BaseModel, Generic[T]), etc.
        """
        name_node = node.child_by_field_name("name")
        if not name_node:
            return
        class_name = _text(name_node, src)

        # Check base classes for BaseModel
        args_node = node.child_by_field_name("superclasses")
        if not args_node:
            return
        bases_text = _text(args_node, src)
        if "BaseModel" not in bases_text and "Schema" not in bases_text:
            return

        model_id = f"model:{class_name}"
        ownership_fields = []
        field_ids = []

        # Walk class body for field annotations
        body = node.child_by_field_name("body")
        if body:
            for stmt in body.children:
                if stmt.type in ("expression_statement",):
                    # Annotated assignment: name: Type = default
                    for expr in stmt.children:
                        if expr.type == "assignment":
                            fname, ftype = self._extract_annotated_assignment(expr, src)
                            if fname:
                                field_id = f"field:{class_name}.{fname}"
                                is_own = _is_ownership_field(fname)
                                if is_own:
                                    ownership_fields.append(fname)
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
                        field_id = f"field:{class_name}.{fname}"
                        is_own = _is_ownership_field(fname)
                        if is_own:
                            ownership_fields.append(fname)
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

        # Add FIELD_OF edges
        for fid in field_ids:
            self.graph.add_edge(Edge(src=fid, dst=model_id, type=EdgeType.FIELD_OF))

    def _extract_annotated_assignment(self, node: TSNode, src: bytes) -> tuple[str, str]:
        """Return (field_name, type_annotation_str) from annotated assignment node."""
        # annotated_assignment: name : type = default
        name_node = node.child_by_field_name("left") or node.child_by_field_name("name")
        type_node = node.child_by_field_name("type") or node.child_by_field_name("annotation")
        if not name_node:
            return "", "Any"
        fname = _text(name_node, src).strip()
        ftype = _text(type_node, src).strip() if type_node else "Any"
        return fname, ftype

    # ── Route extraction ──────────────────────────────────────────────────────

    def _extract_decorated(self, node: TSNode, src: bytes, filepath: str) -> None:
        """
        Handle @app.get("/path") / @router.post("/path") decorated functions.
        """
        decorators = []
        inner = None

        for child in node.children:
            if child.type == "decorator":
                decorators.append(child)
            elif child.type == "function_definition":
                inner = child

        if not inner:
            return

        # Check each decorator for HTTP method patterns
        for dec in decorators:
            endpoint = self._try_extract_route_decorator(dec, src, filepath, inner)
            if endpoint:
                return   # one route decorator per function is enough

        # Not a route — might be a dependency function provider
        self._maybe_extract_dep_function(inner, src, filepath)

    def _try_extract_route_decorator(
        self, dec: TSNode, src: bytes, filepath: str, fn_node: TSNode
    ) -> Optional[EndpointNode]:
        """
        Given a decorator node, try to parse it as a route decorator.
        Returns EndpointNode if successful, None otherwise.
        """
        dec_text = _text(dec, src)

        # Match patterns: @app.get("/path"), @router.post("/path", ...)
        # Also handles: @app.api_route([...], methods=[...])
        method = None
        path = None

        for m in _HTTP_METHODS:
            # e.g. .get( or .GET(
            if re.search(rf"\.{m}\s*\(", dec_text, re.I):
                method = HTTPMethod(m.upper())
                break

        if method is None:
            if "api_route" in dec_text:
                method = HTTPMethod.ANY
            else:
                return None

        # Extract path string from decorator args
        path_match = re.search(r'["\']([/][^"\']*)["\']', dec_text)
        path = path_match.group(1) if path_match else "/"

        fn_name_node = fn_node.child_by_field_name("name")
        fn_name = _text(fn_name_node, src) if fn_name_node else "unknown"
        line = fn_node.start_point[0] + 1

        endpoint_id = f"endpoint:{path}:{method.value}"
        # Deduplicate: if same path+method in multiple files, suffix with file
        if self.graph.get_node(endpoint_id):
            endpoint_id = f"endpoint:{path}:{method.value}:{filepath}"

        # Extract parameters + auth contexts
        params, auth_contexts, auth_required = self._extract_function_params(
            fn_node, src, filepath, endpoint_id
        )

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

        # Add parameter nodes + PARAM_FLOWS_TO edges
        for param in params:
            self.graph.add_node(param)
            self.graph.add_edge(Edge(
                src=param.id,
                dst=endpoint_id,
                type=EdgeType.PARAM_FLOWS_TO,
                auth_contexts=auth_contexts,
            ))

        # Add ENDPOINT_REQUIRES edges for each permission
        for ac in auth_contexts:
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

        # Scan function body for external calls
        body = fn_node.child_by_field_name("body")
        if body:
            self._extract_external_calls(body, src, filepath, endpoint_id, auth_contexts)

        return endpoint

    # ── Parameter extraction ──────────────────────────────────────────────────

    def _extract_function_params(
        self, fn_node: TSNode, src: bytes, filepath: str, endpoint_id: str
    ) -> tuple[list[ParameterNode], list[AuthContext], bool]:
        """
        Parse function signature for FastAPI parameter declarations.
        Returns (param_nodes, auth_contexts, auth_required).
        """
        params: list[ParameterNode] = []
        auth_contexts: list[AuthContext] = []
        auth_required = False

        params_node = fn_node.child_by_field_name("parameters")
        if not params_node:
            return params, auth_contexts, auth_required

        fn_name_node = fn_node.child_by_field_name("name")
        fn_name = _text(fn_name_node, src) if fn_name_node else "fn"

        for param in params_node.named_children:
            if param.type not in ("identifier", "typed_parameter",
                                   "typed_default_parameter", "default_parameter"):
                continue

            param_text = _text(param, src)

            # Skip 'self', 'cls', 'request', 'response', 'background_tasks'
            if re.match(r"^(self|cls|request|response|background_tasks|db)\b", param_text):
                continue

            # Detect Depends(...)
            if "Depends(" in param_text:
                dep_name = self._extract_depends_name(param_text)
                if dep_name:
                    is_auth = _is_auth_dep(dep_name)
                    if is_auth:
                        auth_required = True
                        role = _infer_role(dep_name)
                        ac = AuthContext(
                            role=role,
                            constraint=None,   # we can't statically prove the constraint expr
                            source=dep_name,
                            confidence=0.85,
                        )
                        auth_contexts.append(ac)
                    # Even non-auth Depends may carry implicit auth — flag for manual review
                    elif any(k in dep_name.lower() for k in ["session", "db", "conn"]):
                        pass  # DB dependency, not auth
                    else:
                        # Unknown dependency — low confidence auth possible
                        ac = AuthContext(
                            role="unknown",
                            constraint=None,
                            source=dep_name,
                            confidence=0.4,
                        )
                        auth_contexts.append(ac)
                continue

            # Detect Security(OAuth2PasswordBearer, scopes=...)
            if "Security(" in param_text:
                auth_required = True
                scope_match = re.search(r'scopes\s*=\s*\[([^\]]+)\]', param_text)
                scope = scope_match.group(1).strip('"\'') if scope_match else None
                ac = AuthContext(
                    role="user",
                    constraint=None,
                    source="Security",
                    confidence=0.9,
                )
                auth_contexts.append(ac)
                continue

            # Regular typed parameter
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

        # If no explicit auth found but function signature has 'current_user'
        if not auth_required:
            sig_text = _text(params_node, src)
            if re.search(r"current_user|current_account", sig_text, re.I):
                auth_required = True
                ac = AuthContext(
                    role="user",
                    constraint=None,
                    source="current_user_param",
                    confidence=0.7,
                )
                auth_contexts.append(ac)

        return params, auth_contexts, auth_required

    def _extract_depends_name(self, param_text: str) -> str:
        """Extract the function name from Depends(fn_name) or Depends(fn_name())."""
        m = re.search(r"Depends\(\s*([\w_]+)", param_text)
        return m.group(1) if m else ""

    def _classify_param(
        self, param: TSNode, src: bytes, fn_name: str
    ) -> tuple[str, str, Optional[str], ParamLocation]:
        """
        Classify a parameter by its type annotation to determine FastAPI location.
        Heuristics:
          - Path(...)  → path
          - Query(...) → query
          - Body(...)  → body
          - Header(...)→ header
          - Cookie(...)→ cookie
          - Pydantic model in type annotation → body
          - bare untyped param → query (FastAPI default)
        """
        param_text = _text(param, src)

        # Extract name
        name_match = re.match(r"(\w+)", param_text)
        name = name_match.group(1) if name_match else ""
        if not name:
            return "", "Any", None, ParamLocation.QUERY

        # Extract type annotation
        type_str = "Any"
        type_node = param.child_by_field_name("type")
        if type_node:
            type_str = _text(type_node, src).strip()

        # Extract default value
        default = None
        default_node = param.child_by_field_name("value")
        if default_node:
            default = _text(default_node, src).strip()

        # Determine location by default value expression
        location = ParamLocation.QUERY   # FastAPI default for primitives
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

        # Path params: if param name appears in curly braces of a path, it's PATH
        # (We set this based on naming convention if no explicit Path())
        # This is handled at endpoint level by the caller via path template matching.

        # If type is a known Pydantic model → body
        if type_str in self._pydantic_models:
            location = ParamLocation.BODY

        return name, type_str, default, location

    # ── External call extraction ──────────────────────────────────────────────

    def _extract_external_calls(
        self, body: TSNode, src: bytes, filepath: str,
        endpoint_id: str, auth_contexts: list[AuthContext]
    ) -> None:
        """Scan function body for DB queries and HTTP calls."""
        body_text = _text(body, src)

        # Raw SQL detection
        for pat in _SQL_PATTERNS:
            if pat.search(body_text):
                # Find the line
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
                        break  # one per SQL pattern match is enough

        # ORM call detection (SQLAlchemy, Tortoise, etc.)
        orm_patterns = [
            (r"\.query\(", "db"),
            (r"\.filter\(", "db"),
            (r"\.get\(", "db"),
            (r"await\s+\w+\.find", "db"),
            (r"session\.", "db"),
            (r"httpx\.|requests\.|aiohttp\.", "http"),
        ]
        for pat, call_type in orm_patterns:
            if re.search(pat, body_text):
                call_id = f"ext:{endpoint_id}:{call_type}:{pat[:10].strip()}"
                if not self.graph.get_node(call_id):
                    ext = ExternalCallNode(
                        id=call_id,
                        label=f"{call_type.upper()} call in {endpoint_id}",
                        file=filepath,
                        call_type=call_type,
                    )
                    self.graph.add_node(ext)
                    self.graph.add_edge(Edge(
                        src=endpoint_id,
                        dst=call_id,
                        type=EdgeType.CALLS,
                        auth_contexts=auth_contexts,
                    ))

    # ── Dependency function extraction ────────────────────────────────────────

    def _maybe_extract_dep_function(self, fn_node: TSNode, src: bytes, filepath: str) -> None:
        """
        If this function looks like a FastAPI dependency provider that checks auth,
        register it so routes depending on it get correct auth contexts.
        """
        fn_name_node = fn_node.child_by_field_name("name")
        if not fn_name_node:
            return
        fn_name = _text(fn_name_node, src)

        if not _is_auth_dep(fn_name):
            return

        perm_id = f"perm:{fn_name}"
        if self.graph.get_node(perm_id):
            return  # already registered

        role = _infer_role(fn_name)
        pnode = PermissionNode(
            id=perm_id,
            label=fn_name,
            file=filepath,
            line=fn_node.start_point[0] + 1,
            dependency_fn=fn_name,
            inferred_role=role,
        )
        self.graph.add_node(pnode)
        self._dep_functions[fn_name] = perm_id

    # ── Post-processing: infer path params ───────────────────────────────────

    def enrich_path_params(self) -> None:
        """
        After all files processed: for each endpoint with path template variables
        like /users/{user_id}, ensure a PATH-location param node exists and is
        linked. This catches cases where path params weren't explicitly typed.
        """
        for ep in self.graph.endpoints():
            path_vars = re.findall(r"\{(\w+)\}", ep.path)
            for var in path_vars:
                param_id = f"param:{ep.id}:{var}"
                existing = self.graph.get_node(param_id)
                if not existing:
                    pnode = ParameterNode(
                        id=param_id,
                        label=var,
                        file=ep.file,
                        location=ParamLocation.PATH,
                        python_type="str",
                        required=True,
                        user_controlled=True,
                        metadata={"inferred_from_path_template": True},
                    )
                    self.graph.add_node(pnode)
                    self.graph.add_edge(Edge(
                        src=param_id,
                        dst=ep.id,
                        type=EdgeType.PARAM_FLOWS_TO,
                        auth_contexts=ep.auth_contexts,
                    ))
                else:
                    # Upgrade existing node to PATH if it was guessed as QUERY
                    if isinstance(existing, ParameterNode):
                        existing.location = ParamLocation.PATH
