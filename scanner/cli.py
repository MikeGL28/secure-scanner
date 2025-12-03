# scanner/cli.py

import argparse
import json
import sys
from pathlib import Path
from .analyzers import analyze_python_file
from .formatters.sarif import generate_sarif_report  # импорт нового модуля


def scan_directory(path: Path, output_format: str = "text"):
    if not path.exists():
        print(f"Error: Path {path} does not exist", file=sys.stderr)
        sys.exit(1)

    python_files = path.rglob("*.py") if path.is_dir() else [path]

    all_issues = []
    for py_file in python_files:
        if output_format == "text":
            print(f"🔍 Scanning {py_file}...")
        issues = analyze_python_file(str(py_file))
        for issue in issues:
            # фильтруем технические ошибки (например, syntax_error), если нужно
            if issue.get("type") in ("syntax_error", "parsing_error"):
                continue  # или обрабатывай отдельно
            issue["file"] = str(py_file)
            all_issues.append(issue)

    # Вывод в выбранном формате
    if output_format == "sarif":
        sarif_output = generate_sarif_report(all_issues)
        print(json.dumps(sarif_output, indent=2))
        # Важно: при использовании в CI, exit code должен быть 1 при наличии ошибок
        if any(issue.get("severity", "") in ("high", "critical") for issue in all_issues):
            sys.exit(1)
        else:
            sys.exit(0)
    else:  # text
        if all_issues:
            print("\n🚨 Found issues:")
            for issue in all_issues:
                print(f"  [{issue['severity'].upper()}] {issue['file']}:{issue['line']} — {issue['description']}")
            sys.exit(1)  # завершиться с ошибкой, чтобы GitHub Actions мог поймать
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