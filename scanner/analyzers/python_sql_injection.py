# scanner/analyzers/python_sql_injection.py

import ast
from typing import List, Dict

class SQLInjectionVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues: List[Dict] = []

    def visit_Call(self, node: ast.Call):
        # Ищем вызовы вида cursor.execute(...) или conn.execute(...)
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
            if method_name in ("execute", "executemany"):
                # Первый аргумент — обычно SQL-запрос
                if node.args:
                    query_arg = node.args[0]
                    if isinstance(query_arg, ast.JoinedStr):  # f-строка
                        if self._contains_dynamic_expressions(query_arg):
                            self.issues.append({
                                "type": "sql_injection_risk",
                                "description": "SQL query built using f-string — possible injection",
                                "line": node.lineno,
                                "severity": "high"
                            })
        self.generic_visit(node)

    def _contains_dynamic_expressions(self, joined_str: ast.JoinedStr) -> bool:
        """Проверяет, содержит ли f-строка подстановки (например, {user_input})"""
        for part in joined_str.values:
            if isinstance(part, ast.FormattedValue):
                return True
        return False