# extractors/django_extractor.py
"""
Django AST Extractor

Parses Django applications and populates the StateGraph with:
  - URL patterns from urls.py (path, re_path, include)
  - View authentication (login_required, permission_required, LoginRequiredMixin)
  - Django REST Framework permission classes (IsAuthenticated, IsAdminUser)
  - Model field definitions and ownership markers

Same output shape as FastAPIExtractor — the graph and hypothesis engine
don't care which framework was parsed.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Node as TSNode

from core.graph import (
    StateGraph, EndpointNode, ParameterNode, ModelNode, ModelFieldNode,
    PermissionNode, Edge,
    NodeType, EdgeType, HTTPMethod, ParamLocation, AuthContext,
)

PY_LANGUAGE = Language(tspython.language())
_parser = Parser(PY_LANGUAGE)

# HTTP method → Django class-based view method mapping
_DJANGO_METHOD_MAP = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
}

# Auth decorators
_AUTH_DECORATORS = [
    "login_required",
    "permission_required",
    "user_passes_test",
    "staff_member_required",
    "superuser_required",
]

# DRF permission classes that indicate authentication
_DRF_AUTH_CLASSES = [
    "IsAuthenticated",
    "IsAdminUser",
    "IsAuthenticatedOrReadOnly",
    "DjangoModelPermissions",
    "DjangoObjectPermissions",
]

_OWNERSHIP_FIELDS = re.compile(
    r"(owner|user|created_by|account|tenant)_?id$", re.I
)


def _text(node: TSNode, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _is_ownership_field(name: str) -> bool:
    return bool(_OWNERSHIP_FIELDS.search(name))


class DjangoExtractor:
    """
    Parse Django source files and populate a StateGraph.

    Usage:
        graph = StateGraph()
        extractor = DjangoExtractor(graph)
        extractor.process_urls_file("app/urls.py")
        extractor.process_views_file("app/views.py")
        extractor.process_models_file("app/models.py")
    """

    def __init__(self, graph: StateGraph):
        self.graph = graph
        self._models: dict[str, str] = {}  # model name → node id
        self._views: dict[str, dict] = {}  # view name → {auth_decorators, permissions}
        self._url_patterns: list[dict] = []

    def process_file(self, filepath: str) -> None:
        """Auto-detect file type and process accordingly."""
        src = Path(filepath).read_bytes()
        tree = _parser.parse(src)
        fname = Path(filepath).name

        if "urls" in fname:
            self._extract_urls(tree.root_node, src, filepath)
        elif "model" in fname.lower():
            self._extract_models(tree.root_node, src, filepath)
        elif "view" in fname.lower():
            self._extract_views(tree.root_node, src, filepath)
        else:
            # Generic module — scan for all patterns
            self._extract_models(tree.root_node, src, filepath)
            self._extract_views(tree.root_node, src, filepath)
            self._extract_urls(tree.root_node, src, filepath)

    def build_endpoints(self) -> None:
        """After processing all files, build endpoint nodes from url patterns."""
        for pattern in self._url_patterns:
            self._create_endpoint_from_pattern(pattern)

    # ── URL extraction ───────────────────────────────────────────────────

    def _extract_urls(self, root: TSNode, src: bytes, filepath: str) -> None:
        """Parse urlpatterns list for path() and re_path() calls."""
        self._walk_for_urlpatterns(root, src, filepath)

    def _walk_for_urlpatterns(self, node: TSNode, src: bytes, filepath: str) -> None:
        """Recursively find urlpatterns assignments."""
        if node.type == "assignment":
            left = node.child_by_field_name("left")
            if left and _text(left, src).strip() == "urlpatterns":
                right = node.child_by_field_name("right")
                if right:
                    self._parse_urlpatterns_list(right, src, filepath)

        for child in node.children:
            self._walk_for_urlpatterns(child, src, filepath)

    def _parse_urlpatterns_list(self, node: TSNode, src: bytes, filepath: str) -> None:
        """Parse a list of path()/re_path()/include() calls."""
        if node.type not in ("list", "list_comprehension"):
            return

        for child in node.children:
            call_text = _text(child, src)
            # path('route/', view, name='...')
            if "path(" in call_text or "re_path(" in call_text:
                route = self._extract_route_string(child, src)
                view_name = self._extract_view_name(child, src)
                methods = self._infer_methods_from_view(view_name)

                for method in methods:
                    self._url_patterns.append({
                        "route": route,
                        "view": view_name,
                        "method": method,
                        "file": filepath,
                        "line": child.start_point[0] + 1,
                    })
            # include('app.urls')
            elif "include(" in call_text:
                # In a full implementation, resolve the included file
                pass

    def _extract_route_string(self, node: TSNode, src: bytes) -> str:
        """Extract the first string argument from a function call."""
        args = node.child_by_field_name("arguments")
        if args:
            for child in args.children:
                if child.type == "string":
                    return _text(child, src).strip("'\"")
        return "/"

    def _extract_view_name(self, node: TSNode, src: bytes) -> str:
        """Extract the view function or class name from a path() call."""
        call_text = _text(node, src)
        # path('route/', views.MyView.as_view())
        if ".as_view()" in call_text:
            match = re.search(r"(\w+)\.as_view\(\)", call_text)
            return match.group(1) if match else "unknown"
        # path('route/', view_function)
        match = re.search(r"""['"]\s*,\s*(\w+)""", call_text)
        return match.group(1) if match else "unknown"

    def _infer_methods_from_view(self, view_name: str) -> list[str]:
        """Given a view name, infer which HTTP methods it handles."""
        if view_name in self._views:
            view_info = self._views[view_name]
            if "methods" in view_info:
                return view_info["methods"]
        # Default: Django view handles GET
        return ["GET"]

    # ── View extraction ──────────────────────────────────────────────────

    def _extract_views(self, root: TSNode, src: bytes, filepath: str) -> None:
        """Find view functions and extract auth decorators."""
        for child in root.children:
            if child.type == "decorated_definition":
                self._extract_decorated_view(child, src, filepath)
            elif child.type == "class_definition":
                self._extract_class_based_view(child, src, filepath)

    def _extract_decorated_view(self, node: TSNode, src: bytes, filepath: str) -> None:
        """Extract a @login_required decorated function-based view."""
        name_node = None
        decorators = []
        for child in node.children:
            if child.type == "decorator":
                dec_text = _text(child, src)
                decorators.append(dec_text)
            elif child.type == "function_definition":
                name_node = child.child_by_field_name("name")

        if not name_node:
            return
        view_name = _text(name_node, src)

        auth_required = False
        permissions = []
        for dec in decorators:
            for auth_dec in _AUTH_DECORATORS:
                if auth_dec in dec:
                    auth_required = True
                    if "permission_required" in dec:
                        perm_match = re.search(r"""permission_required\(['"]([^'"]+)['"]""", dec)
                        if perm_match:
                            permissions.append(perm_match.group(1))
                    break

        self._views[view_name] = {
            "type": "function",
            "auth_required": auth_required,
            "permissions": permissions,
            "file": filepath,
            "line": node.start_point[0] + 1,
        }

    def _extract_class_based_view(self, node: TSNode, src: bytes, filepath: str) -> None:
        """Extract a Django REST Framework ViewSet or Django View."""
        name_node = node.child_by_field_name("name")
        if not name_node:
            return
        class_name = _text(name_node, src)

        # Check bases for DRF ViewSet/APIView
        bases = node.child_by_field_name("superclasses")
        bases_text = _text(bases, src) if bases else ""
        is_drf = any(k in bases_text for k in ("ViewSet", "APIView", "GenericAPIView"))

        auth_required = False
        permission_classes = []
        methods = ["GET"]  # default

        body = node.child_by_field_name("body")
        if body:
            for stmt in body.children:
                stmt_text = _text(stmt, src)
                # permission_classes = [IsAuthenticated]
                if "permission_classes" in stmt_text:
                    for drf_class in _DRF_AUTH_CLASSES:
                        if drf_class in stmt_text:
                            auth_required = True
                            permission_classes.append(drf_class)
                # authentication_classes = [...]
                if "authentication_classes" in stmt_text:
                    auth_required = True
                # Detect HTTP method handlers
                for http_method in _DJANGO_METHOD_MAP:
                    if f"def {http_method}(" in stmt_text:
                        methods.append(_DJANGO_METHOD_MAP[http_method])

        self._views[class_name] = {
            "type": "class",
            "auth_required": auth_required,
            "permissions": permission_classes,
            "is_drf": is_drf,
            "methods": list(set(methods)),
            "file": filepath,
            "line": node.start_point[0] + 1,
        }

    # ── Model extraction ─────────────────────────────────────────────────

    def _extract_models(self, root: TSNode, src: bytes, filepath: str) -> None:
        """Extract Django Model class definitions."""
        for child in root.children:
            if child.type == "class_definition":
                name_node = child.child_by_field_name("name")
                if not name_node:
                    continue
                class_name = _text(name_node, src)

                # Check if it extends models.Model
                bases = child.child_by_field_name("superclasses")
                bases_text = _text(bases, src) if bases else ""
                if "Model" not in bases_text and "models.Model" not in bases_text:
                    continue

                model_id = f"model:{class_name}"
                ownership_fields = []
                field_ids = []

                body = child.child_by_field_name("body")
                if body:
                    for stmt in body.children:
                        if stmt.type == "expression_statement":
                            stmt_text = _text(stmt, src)
                            # models.CharField(...), models.ForeignKey(...)
                            field_match = re.match(r"(\w+)\s*=\s*models\.\w+", stmt_text)
                            if field_match:
                                fname = field_match.group(1)
                                field_id = f"field:{class_name}.{fname}"
                                is_own = _is_ownership_field(fname)
                                if is_own:
                                    ownership_fields.append(fname)

                                fnode = ModelFieldNode(
                                    id=field_id,
                                    label=fname,
                                    file=filepath,
                                    line=stmt.start_point[0] + 1,
                                    field_type="string",
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
                self._models[class_name] = model_id

                for fid in field_ids:
                    self.graph.add_edge(Edge(src=fid, dst=model_id, type=EdgeType.FIELD_OF))

    # ── Endpoint creation ────────────────────────────────────────────────

    def _create_endpoint_from_pattern(self, pattern: dict) -> None:
        """Create an EndpointNode from a URL pattern."""
        route = pattern["route"]
        view_name = pattern["view"]
        method = pattern["method"]
        filepath = pattern.get("file", "")

        # Normalize Django URL parameters: <int:pk> → {pk}
        normalized_route = re.sub(r"<[^:]+:([^>]+)>", r"{\1}", route)

        endpoint_id = f"endpoint:{normalized_route}:{method}"
        if self.graph.get_node(endpoint_id):
            return

        auth_required = False
        auth_contexts = []
        permissions = []

        if view_name in self._views:
            view_info = self._views[view_name]
            auth_required = view_info.get("auth_required", False)
            permissions = view_info.get("permissions", [])

            if auth_required:
                for perm in permissions:
                    ac = AuthContext(
                        role="user",
                        constraint=perm,
                        source=view_name,
                        confidence=0.85,
                    )
                    auth_contexts.append(ac)

        ep = EndpointNode(
            id=endpoint_id,
            label=f"{method} {normalized_route}",
            file=filepath,
            line=pattern.get("line", 0),
            method=HTTPMethod(method),
            path=normalized_route,
            function_name=view_name,
            auth_contexts=auth_contexts,
            auth_required=auth_required,
        )
        self.graph.add_node(ep)

        # Extract path params from route
        path_vars = re.findall(r"\{(\w+)\}", normalized_route)
        for var in path_vars:
            param_id = f"param:{endpoint_id}:{var}"
            if not self.graph.get_node(param_id):
                pnode = ParameterNode(
                    id=param_id,
                    label=var,
                    location=ParamLocation.PATH,
                    python_type="str",
                    required=True,
                    user_controlled=True,
                )
                self.graph.add_node(pnode)
                self.graph.add_edge(Edge(
                    src=param_id,
                    dst=endpoint_id,
                    type=EdgeType.PARAM_FLOWS_TO,
                    auth_contexts=ep.auth_contexts,
                ))

        # Add permission edges
        for ac in auth_contexts:
            perm_id = f"perm:{ac.source}"
            if not self.graph.get_node(perm_id):
                pnode = PermissionNode(
                    id=perm_id,
                    label=ac.source,
                    dependency_fn=ac.source,
                )
                self.graph.add_node(pnode)
            self.graph.add_edge(Edge(
                src=endpoint_id,
                dst=perm_id,
                type=EdgeType.ENDPOINT_REQUIRES,
                auth_contexts=[ac],
            ))
