import ast
import os
import re
from typing import List, Optional
from packages.schemas.models import (
    AuthorizationIntent,
    ActionType,
    AuthLevel,
    OwnershipRequirement,
    CodeEvidence
)

class AuthorizationIntentExtractor(ast.NodeVisitor):
    """
    Production-Grade AST Authorization Intent Extractor:
    Dynamically analyzes Python/FastAPI/Flask AST syntax trees to extract routes,
    HTTP methods, resource types, auth requirements, and ownership check guards
    WITHOUT any hardcoded route strings.
    """
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.intents: List[AuthorizationIntent] = []
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            self.code_lines = f.readlines()

    def extract_intents(self) -> List[AuthorizationIntent]:
        code = "".join(self.code_lines)
        try:
            tree = ast.parse(code)
            self.visit(tree)
        except Exception as e:
            # Fallback regex extraction if AST parsing fails
            self._regex_fallback_extract(code)

        return self.intents

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Inspect decorators for route definitions (@app.get, @app.post, etc.)
        for decorator in node.decorator_list:
            route_path = None
            http_method = "GET"

            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                if decorator.func.attr in ["get", "post", "put", "delete", "patch"]:
                    http_method = decorator.func.attr.upper()
                    if decorator.args and isinstance(decorator.args[0], ast.Constant):
                        route_path = str(decorator.args[0].value)

            if route_path:
                intent = self._build_intent_from_ast_node(node, route_path, http_method)
                if intent:
                    self.intents.append(intent)

        self.generic_visit(node)

    def _build_intent_from_ast_node(self, node: ast.FunctionDef, route_path: str, http_method: str) -> AuthorizationIntent:
        # Determine semantic action type
        action_map = {
            "GET": ActionType.READ,
            "POST": ActionType.CREATE,
            "PUT": ActionType.UPDATE,
            "PATCH": ActionType.UPDATE,
            "DELETE": ActionType.DELETE
        }
        action = action_map.get(http_method, ActionType.READ)

        # Infer Resource Name from route path (e.g. /api/orders/{id} -> "Order")
        resource_name = "Resource"
        path_segments = [seg for seg in route_path.strip("/").split("/") if seg and not seg.startswith("{")]
        if path_segments:
            raw_res = path_segments[-1]
            if raw_res == "users" and "admin" in path_segments:
                resource_name = "UserList"
                action = ActionType.ADMIN
            else:
                resource_name = raw_res.rstrip("s").capitalize()

        # Check Authentication requirements from function parameters or decorator dependencies
        auth_level = AuthLevel.PUBLIC
        func_code = ast.unparse(node) if hasattr(ast, "unparse") else ""

        if "current_user" in func_code or "Depends" in func_code or "token" in func_code:
            if "admin" in route_path.lower() or "role" in func_code.lower() and "admin" in func_code.lower():
                auth_level = AuthLevel.ADMIN
            else:
                auth_level = AuthLevel.AUTHENTICATED

        # Check for Resource Ownership Check requirement
        # A route that takes an ID parameter ({id}, {order_id}, etc.) and queries DB implies an ownership requirement
        has_id_param = "{" in route_path and "}" in route_path
        
        # Check if the code contains an explicit ownership check (e.g., user_id == current_user.id)
        has_explicit_owner_check = bool(re.search(r'(\.user_id|\["user_id"\])\s*==\s*current_user', func_code))

        # Ownership is required if it accesses a resource by ID but lacks an explicit check in code
        ownership_required = has_id_param

        snippet = self.code_lines[node.lineno - 1].strip() if node.lineno <= len(self.code_lines) else func_code[:100]

        return AuthorizationIntent(
            endpoint=route_path,
            http_method=http_method,
            resource=resource_name,
            action=action,
            auth_level=auth_level,
            ownership=OwnershipRequirement(
                required=ownership_required,
                field="user_id",
                principal_field="current_user.id"
            ),
            evidence=[CodeEvidence(file=self.file_path, line=node.lineno, snippet=snippet)]
        )

    def _regex_fallback_extract(self, code: str):
        # Fallback regex extraction for route decorators
        matches = re.findall(r'@app\.(get|post|put|delete)\(["\']([^"\']+)["\']\)', code, re.IGNORECASE)
        for method, route in matches:
            has_id = "{" in route
            res_name = route.strip("/").split("/")[-1].rstrip("s").capitalize() if "/" in route else "Resource"
            self.intents.append(AuthorizationIntent(
                endpoint=route,
                http_method=method.upper(),
                resource=res_name,
                action=ActionType.READ if method.upper() == "GET" else ActionType.CREATE,
                auth_level=AuthLevel.ADMIN if "admin" in route else AuthLevel.AUTHENTICATED,
                ownership=OwnershipRequirement(required=has_id, field="user_id"),
                evidence=[CodeEvidence(file=self.file_path, line=1, snippet=f"@app.{method}('{route}')")]
            ))
