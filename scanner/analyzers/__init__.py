# scanner/analyzers/__init__.py

import ast
from typing import List, Dict
from pathlib import Path

# Импортируем наши анализаторы
from .python_sql_injection import SQLInjectionVisitor
from .python_dangerous_funcs import DangerousEvalVisitor


def analyze_python_file(filepath: str) -> List[Dict]:
    """
    Анализирует один Python-файл на наличие уязвимостей.
    Возвращает список найденных проблем.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as e:
        return [{
            "type": "syntax_error",
            "description": f"SyntaxError: {e.msg}",
            "line": e.lineno or 1,
            "severity": "error"
        }]
    except Exception as e:
        return [{
            "type": "parsing_error",
            "description": f"Failed to parse {filepath}: {str(e)}",
            "line": 1,
            "severity": "error"
        }]

    issues = []

    # Запускаем все анализаторы
    visitors = [
        SQLInjectionVisitor(),
        DangerousEvalVisitor(),
        # Добавь сюда новые анализаторы по мере разработки
    ]

    for visitor in visitors:
        visitor.visit(tree)
        issues.extend(visitor.issues)

    return issues