# scanner/api.py

from fastapi import FastAPI, UploadFile, File, HTTPException
from pathlib import Path
import tempfile
import shutil
from .dependency_check import parse_requirements, parse_pyproject_toml, check_vulnerabilities
from .analyzers import analyze_python_file

app = FastAPI(title="Secure Scanner API", version="0.1.0")


def _should_skip_path(path: Path) -> bool:
    """Возвращает True, если путь нужно пропустить при сканировании."""
    skip_patterns = {".venv", "venv", "__pycache__", ".git", "node_modules", ".mypy_cache", ".pytest_cache", ".tox", "dist", "build"}
    return any(part in skip_patterns for part in path.parts)


@app.post("/scan")
async def scan_code(file: UploadFile = File(...)):
    if not file.filename.endswith(".zip"):
        raise HTTPException(400, detail="Only .zip archives supported")

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = Path(tmpdir) / file.filename
        with open(zip_path, "wb") as f:
            f.write(await file.read())

        extract_dir = Path(tmpdir) / "extracted"
        shutil.unpack_archive(zip_path, extract_dir)

        # === Анализ Python-файлов ===
        all_issues = []
        for py_file in extract_dir.rglob("*.py"):
            if _should_skip_path(py_file):
                continue
            issues = analyze_python_file(str(py_file))
            for issue in issues:
                if issue.get("type") in ("syntax_error", "parsing_error"):
                    continue
                # Относительный путь от корня архива
                issue["file"] = str(py_file.relative_to(extract_dir))
                all_issues.append(issue)

        # === Анализ зависимостей ===
        req_file = extract_dir / "requirements.txt"
        if req_file.exists():
            deps = parse_requirements(req_file)
            dep_issues = check_vulnerabilities(deps, source_file="requirements.txt")
            # Исправляем путь файла для вывода
            for issue in dep_issues:
                issue["file"] = "requirements.txt"
            all_issues.extend(dep_issues)
        else:
            pyproject_file = extract_dir / "pyproject.toml"
            if pyproject_file.exists():
                deps = parse_pyproject_toml(pyproject_file)
                dep_issues = check_vulnerabilities(deps, source_file="pyproject.toml")
                for issue in dep_issues:
                    issue["file"] = "pyproject.toml"
                all_issues.extend(dep_issues)

        return {
            "status": "completed",
            "issues_count": len(all_issues),
            "issues": all_issues
        }