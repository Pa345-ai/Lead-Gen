# extractors/express_extractor.py
"""
Express.js AST Extractor

Parses Node.js/Express applications and populates the StateGraph with:
  - Route definitions (router.get, router.post, app.use)
  - Middleware chains (passport.authenticate, jwt, requireAuth)
  - Request parameters (req.params.id, req.body.*, req.query.*)
  - Model/schema definitions from Joi, Zod, or TypeScript interfaces

Uses tree-sitter-javascript for AST parsing.
Same output shape as FastAPIExtractor — framework-agnostic graph.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

try:
    import tree_sitter_javascript as tsjs
    from tree_sitter import Language, Parser, Node as TSNode
    JS_LANGUAGE = Language(tsjs.language())
    _parser = Parser(JS_LANGUAGE)
except ImportError:
    JS_LANGUAGE = None
    _parser = None

from core.graph import (
    StateGraph, EndpointNode, ParameterNode, ModelNode, ModelFieldNode,
    PermissionNode, Edge,
    NodeType, EdgeType, HTTPMethod, ParamLocation, AuthContext,
)


# Express HTTP method names
_EXPRESS_METHODS = {
    "get", "post", "put", "patch", "delete", "head", "options", "all", "use",
}

# Auth middleware patterns
_AUTH_MIDDLEWARE = [
    "passport.authenticate",
    "jwt(",
    "requireAuth",
    "checkRole",
    "verifyToken",
    "isAuthenticated",
    "authGuard",
    "authorize(",
    "checkJwt",
    "ensureLoggedIn",
]

# Parameter extraction patterns
_REQ_PARAM_PATTERNS = [
    (r"req\.params\.(\w+)", "path"),
    (r"req\.query\.(\w+)", "query"),
    (r"req\.body\.(\w+)", "body"),
    (r"req\.headers\[['\"](\w+)['\"]\]", "header"),
    (r"req\.cookies\.(\w+)", "cookie"),
]

_OWNERSHIP_FIELDS = re.compile(
    r"(owner|user|createdBy|account|tenant|org)Id$", re.I
)


def _text(node: TSNode, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


class ExpressExtractor:
    """
    Parse Express.js source files and populate a StateGraph.

    Usage:
        graph = StateGraph()
        extractor = ExpressExtractor(graph)
        extractor.process_file("routes/orders.js")
        extractor.process_file("routes/users.ts")
    """

    def __init__(self, graph: StateGraph):
        if _parser is None:
            raise ImportError(
                "tree-sitter-javascript not installed. "
                "Install with: pip install tree-sitter-javascript"
            )
        self.graph = graph

    def process_file(self, filepath: str) -> None:
        src = Path(filepath).read_bytes()
        tree = _parser.parse(src)
        self._walk_module(tree.root_node, src, str(filepath))

    def _walk_module(self, root: TSNode, src: bytes, filepath: str) -> None:
        """Find route definitions and model schemas."""
        for child in root.children:
            self._extract_route_calls(child, src, filepath)
            self._extract_schema_definitions(child, src, filepath)

    # ── Route extraction ─────────────────────────────────────────────────

    def _extract_route_calls(self, node: TSNode, src: bytes, filepath: str) -> None:
        """Find router.get('/path', middleware, handler) patterns."""
        if node.type == "expression_statement":
            call_node = self._find_call_expression(node)
            if call_node:
                self._parse_route_call(call_node, src, filepath)

        for child in node.children:
            self._extract_route_calls(child, src, filepath)

    def _find_call_expression(self, node: TSNode) -> Optional[TSNode]:
        """Navigate to the call_expression child."""
        for child in node.children:
            if child.type == "call_expression":
                return child
            result = self._find_call_expression(child)
            if result:
                return result
        return None

    def _parse_route_call(self, call_node: TSNode, src: bytes, filepath: str) -> None:
        """Parse a single router.get() or app.post() call."""
        call_text = _text(call_node, src)

        # Detect HTTP method: router.get( ... )
        for method in _EXPRESS_METHODS:
            if f".{method}(" in call_text or f"['{method}'](" in call_text:
                http_method = HTTPMethod(method.upper() if method != "all" else "ANY")
                break
        else:
            return

        # Extract path argument
        path = "/"
        args = call_node.child_by_field_name("arguments")
        if args:
            for i, child in enumerate(args.children):
                if child.type == "string":
                    path = _text(child, src).strip("'\"")
                    break
                elif child.type == "template_string":
                    path = self._normalize_template_string(_text(child, src))

        # Detect auth middleware in the argument list
        auth_detected = False
        auth_middleware_name = ""
        if args:
            args_text = _text(args, src)
            for auth_pattern in _AUTH_MIDDLEWARE:
                if auth_pattern in args_text:
                    auth_detected = True
                    auth_middleware_name = auth_pattern
                    break

        # Normalize path params: /orders/:id → /orders/{id}
        normalized_path = re.sub(r":(\w+)", r"{\1}", path)

        endpoint_id = f"endpoint:{normalized_path}:{http_method.value}"
        if self.graph.get_node(endpoint_id):
            endpoint_id = f"endpoint:{normalized_path}:{http_method.value}:{filepath}"

        auth_contexts = []
        if auth_detected:
            ac = AuthContext(
                role="user",
                constraint=None,
                source=auth_middleware_name,
                confidence=0.8,
            )
            auth_contexts.append(ac)

        ep = EndpointNode(
            id=endpoint_id,
            label=f"{http_method.value} {normalized_path}",
            file=filepath,
            line=call_node.start_point[0] + 1,
            method=http_method,
            path=normalized_path,
            function_name="express_handler",
            auth_contexts=auth_contexts,
            auth_required=auth_detected,
        )
        self.graph.add_node(ep)

        # Extract params from req.params, req.query, req.body in the handler body
        self._extract_request_params(call_node, src, filepath, endpoint_id, auth_contexts)

        # Add path params from route pattern
        path_vars = re.findall(r"\{(\w+)\}", normalized_path)
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

        # Add permission nodes for auth middleware
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

    def _extract_request_params(
        self, call_node: TSNode, src: bytes, filepath: str,
        endpoint_id: str, auth_contexts: list,
    ) -> None:
        """Scan the callback body for req.params.X, req.query.X, req.body.X."""
        # Walk the entire call_expression to find statement_blocks/arrow_functions
        body_text = _text(call_node, src)
        for pattern, location in _REQ_PARAM_PATTERNS:
            for match in re.finditer(pattern, body_text):
                param_name = match.group(1)
                param_id = f"param:{endpoint_id}:{param_name}"
                if not self.graph.get_node(param_id):
                    pnode = ParameterNode(
                        id=param_id,
                        label=param_name,
                        file=filepath,
                        location=ParamLocation(location),
                        python_type="str",
                        required=location == "path",
                        user_controlled=True,
                    )
                    self.graph.add_node(pnode)
                    self.graph.add_edge(Edge(
                        src=param_id,
                        dst=endpoint_id,
                        type=EdgeType.PARAM_FLOWS_TO,
                        auth_contexts=auth_contexts,
                    ))

    # ── Schema extraction ────────────────────────────────────────────────

    def _extract_schema_definitions(self, node: TSNode, src: bytes, filepath: str) -> None:
        """Extract Joi schemas, Zod schemas, or TypeScript interfaces as ModelNodes."""
        node_text = _text(node, src)

        # Joi schema: const orderSchema = Joi.object({ ... })
        if "Joi.object(" in node_text or "joi.object(" in node_text:
            match = re.search(r"(\w+)\s*=\s*[Jj]oi\.object\(\{", node_text)
            if match:
                schema_name = match.group(1)
                fields = re.findall(r"(\w+):\s*[Jj]oi\.", node_text)
                self._create_model_from_fields(schema_name, fields, filepath)

        # Zod schema: const OrderSchema = z.object({ ... })
        if "z.object(" in node_text:
            match = re.search(r"(\w+)\s*=\s*z\.object\(\{", node_text)
            if match:
                schema_name = match.group(1)
                fields = re.findall(r"(\w+):\s*z\.", node_text)
                self._create_model_from_fields(schema_name, fields, filepath)

        for child in node.children:
            self._extract_schema_definitions(child, src, filepath)

    def _create_model_from_fields(self, name: str, field_names: list[str], filepath: str) -> None:
        """Create a ModelNode from extracted field names."""
        model_id = f"model:{name}"
        if self.graph.get_node(model_id):
            return

        ownership_fields = []
        field_ids = []
        for fname in field_names:
            if fname in ("id", "_id", "__v"):
                continue
            field_id = f"field:{name}.{fname}"
            is_own = bool(_OWNERSHIP_FIELDS.search(fname))
            if is_own:
                ownership_fields.append(fname)

            fnode = ModelFieldNode(
                id=field_id,
                label=fname,
                file=filepath,
                field_type="string",
                parent_model=model_id,
                is_ownership_marker=is_own,
            )
            self.graph.add_node(fnode)
            field_ids.append(field_id)

        model_node = ModelNode(
            id=model_id,
            label=name,
            file=filepath,
            fields=field_ids,
            ownership_fields=ownership_fields,
        )
        self.graph.add_node(model_node)

        for fid in field_ids:
            self.graph.add_edge(Edge(src=fid, dst=model_id, type=EdgeType.FIELD_OF))

    # ── Helpers ──────────────────────────────────────────────────────────

    def _normalize_template_string(self, ts: str) -> str:
        """Convert ES6 template literal path to normalized form."""
        # `/users/${id}` → /users/{id}
        return re.sub(r"\$\{(\w+)\}", r"{\1}", ts.strip("`"))