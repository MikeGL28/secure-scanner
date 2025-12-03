import ast
import sys

class DangerousEvalVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec"):
                self.issues.append({
                    "type": "dangerous_function",
                    "function": node.func.id,
                    "line": node.lineno,
                    "severity": "high"
                })
        self.generic_visit(node)

def analyze_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        try:
            tree = ast.parse(f.read(), filename=filepath)
        except SyntaxError:
            print(f"⚠️  Syntax error in {filepath} — skipping", file=sys.stderr)
            return []
    visitor = DangerousEvalVisitor()
    visitor.visit(tree)
    return visitor.issues