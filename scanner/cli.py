# scanner/cli.py

import argparse
import json
import sys
from pathlib import Path
from .analyzers import analyze_python_file
from .formatters.sarif import generate_sarif_report
from .dependency_check import (
    parse_requirements,
    parse_pyproject_toml,
    check_vulnerabilities
)


def _should_skip_path(path: Path) -> bool:
    """Возвращает True, если путь нужно пропустить при сканировании."""
    skip_patterns = {".venv", "venv", "__pycache__", ".git", "node_modules", ".mypy_cache", ".pytest_cache", ".tox", "dist", "build"}
    return any(part in skip_patterns for part in path.parts)


def scan_directory(path: Path, output_format: str = "text"):
    if not path.exists():
        print(f"Error: Path {path} does not exist", file=sys.stderr)
        sys.exit(1)

    # === 1. Сбор и фильтрация Python-файлов ===
    if path.is_dir():
        all_python_files = path.rglob("*.py")
        python_files = [f for f in all_python_files if not _should_skip_path(f)]
    elif path.suffix == ".py":
        python_files = [path] if not _should_skip_path(path) else []
    else:
        print(f"Warning: {path} is not a Python file or directory. Skipping code analysis.", file=sys.stderr)
        python_files = []

    code_issues = []
    for py_file in python_files:
        if output_format == "text":
            print(f"🔍 Scanning {py_file}...")
        issues = analyze_python_file(str(py_file))
        for issue in issues:
            if issue.get("type") in ("syntax_error", "parsing_error"):
                continue
            issue["file"] = str(py_file)
            code_issues.append(issue)

    # === 2. Анализ зависимостей ===
    dep_issues = []
    base_dir = path if path.is_dir() else path.parent

    # Сначала пытаемся прочитать requirements.txt
    req_file = base_dir / "requirements.txt"
    if req_file.exists():
        if output_format == "text":
            print(f"🔍 Checking dependencies in {req_file}...")
        deps = parse_requirements(req_file)
        dep_issues = check_vulnerabilities(deps, source_file="requirements.txt")
    else:
        # Если requirements.txt нет — пробуем pyproject.toml
        pyproject_file = base_dir / "pyproject.toml"
        if pyproject_file.exists():
            if output_format == "text":
                print(f"🔍 Checking dependencies in {pyproject_file}...")
            deps = parse_pyproject_toml(pyproject_file)
            dep_issues = check_vulnerabilities(deps, source_file="pyproject.toml")

    # === 3. Объединение и вывод ===
    all_issues = code_issues + dep_issues

    if output_format == "sarif":
        sarif_output = generate_sarif_report(all_issues)
        print(json.dumps(sarif_output, indent=2))
        has_critical = any(
            issue.get("severity", "").lower() in ("high", "critical")
            for issue in all_issues
        )
        sys.exit(1 if has_critical else 0)

    else:  # text
        if all_issues:
            print("\n🚨 Found issues:")
            for issue in all_issues:
                print(f"  [{issue['severity'].upper()}] {issue['file']}:{issue['line']} — {issue['description']}")
            sys.exit(1)
        else:
            print("✅ No issues found.")
            sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Secure Scanner: Static code analyzer for Python")
    parser.add_argument("--path", required=True, help="Path to Python file or directory")
    parser.add_argument(
        "--format",
        choices=["text", "sarif"],
        default="text",
        help="Output format (default: text)"
    )
    args = parser.parse_args()

    scan_directory(Path(args.path), output_format=args.format)


if __name__ == "__main__":
    main()