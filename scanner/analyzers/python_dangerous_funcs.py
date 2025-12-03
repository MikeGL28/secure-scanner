# scanner/analyzers/python_dangerous_funcs.py

import ast
from typing import List, Dict

class DangerousEvalVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues: List[Dict] = []

    def visit_Call(self, node: ast.Call):
        # Проверяем вызовы вида eval(...), exec(...)
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ("eval", "exec"):
                self.issues.append({
                    "type": "dangerous_function",
                    "description": f"Use of dangerous function `{func_name}()`",
                    "line": node.lineno,
                    "severity": "high"
                })

        # Проверяем pickle.loads, yaml.load (без SafeLoader), etc.
        elif isinstance(node.func, ast.Attribute):
            # pickle.loads(...)
            if (isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle" and node.func.attr == "loads"):
                self.issues.append({
                    "type": "unsafe_deserialization",
                    "description": "Use of `pickle.loads()` — insecure deserialization",
                    "line": node.lineno,
                    "severity": "critical"
                })

            # yaml.load(...) без SafeLoader
            elif (isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml" and node.func.attr == "load"):
                self.issues.append({
                    "type": "unsafe_deserialization",
                    "description": "Use of `yaml.load()` without SafeLoader — may lead to RCE",
                    "line": node.lineno,
                    "severity": "high"
                })

        self.generic_visit(node)