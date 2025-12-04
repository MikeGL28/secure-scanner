# scanner/core.py

import sys
from pathlib import Path
from typing import List, Dict
from .analyzers import analyze_python_file
from .dependency_check import parse_requirements, check_vulnerabilities


def _should_skip_path(path: Path) -> bool:
    skip_patterns = {".venv", "venv", "__pycache__", ".git", "node_modules"}
    return any(part in skip_patterns for part in path.parts)


def analyze_project(path: Path) -> List[Dict]:
    """Анализирует проект: код + зависимости. Возвращает список issue."""
    all_issues = []

    # Анализ Python-файлов
    if path.is_dir():
        python_files = [f for f in path.rglob("*.py") if not _should_skip_path(f)]
    elif path.suffix == ".py":
        python_files = [path] if not _should_skip_path(path) else []
    else:
        python_files = []

    for py_file in python_files:
        issues = analyze_python_file(str(py_file))
        for issue in issues:
            if issue.get("type") in ("syntax_error", "parsing_error"):
                continue
            issue["file"] = str(py_file)
            all_issues.append(issue)

    # Анализ зависимостей
    base_dir = path if path.is_dir() else path.parent
    req_file = base_dir / "requirements.txt"
    if req_file.exists():
        deps = parse_requirements(req_file)
        all_issues.extend(check_vulnerabilities(deps, source_file="requirements.txt"))
    else:
        pyproject_file = base_dir / "pyproject.toml"
        if pyproject_file.exists():
            from .dependency_check import parse_pyproject_toml
            deps = parse_pyproject_toml(pyproject_file)
            all_issues.extend(check_vulnerabilities(deps, source_file="pyproject.toml"))

    return all_issues