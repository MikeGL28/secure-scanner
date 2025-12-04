# scanner/dependency_check.py

import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import requests

# Совместимый импорт TOML
try:
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib
except ImportError:
    tomllib = None

OSV_API_URL = "https://api.osv.dev/v1/querybatch"


def parse_requirements(requirements_path: Path) -> List[Dict[str, str]]:
    """
    Парсит requirements.txt и возвращает список: [{"name": "django", "version": "3.2.0"}, ...]
    Поддерживает только точные версии: package==1.2.3
    """
    if not requirements_path.exists():
        return []

    deps = []
    with open(requirements_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line = line.split("#")[0].strip()
            match = re.match(r"^([a-zA-Z0-9._-]+)(==)([^\s,]+)", line)
            if match:
                name = match.group(1).lower()
                version = match.group(3).strip()
                deps.append({"name": name, "version": version})
    return deps


def parse_pyproject_toml(pyproject_path: Path) -> List[Dict[str, str]]:
    """Парсит зависимости из pyproject.toml (Poetry и PEP 621)."""
    if tomllib is None:
        print("⚠️  tomli/tomllib not available. Skipping pyproject.toml.", file=sys.stderr)
        return []
    if not pyproject_path.exists():
        return []

    try:
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        print(f"⚠️  Failed to parse {pyproject_path}: {e}", file=sys.stderr)
        return []

    deps = []

    # Poetry: [tool.poetry.dependencies]
    if "tool" in data and "poetry" in data["tool"]:
        poetry_deps = data["tool"]["poetry"].get("dependencies", {})
        for name, spec in poetry_deps.items():
            if name.lower() == "python":
                continue
            version = _extract_pinned_version(spec)
            if version:
                deps.append({"name": name, "version": version})

    # PEP 621: [project.dependencies]
    if "project" in data and "dependencies" in data["project"]:
        for dep_str in data["project"]["dependencies"]:
            name, version = _parse_pep508_dependency(dep_str)
            if version:
                deps.append({"name": name, "version": version})

    return deps


def _extract_pinned_version(spec) -> Optional[str]:
    """Извлекает точную версию из Poetry-спецификации (только строка вида '3.2.0')"""
    if isinstance(spec, str) and re.match(r"^\d+\.\d+\.\d+", spec):
        return spec
    return None


def _parse_pep508_dependency(dep_str: str) -> Tuple[str, Optional[str]]:
    """Парсит 'package==1.2.3' → ('package', '1.2.3')"""
    match = re.match(r"^([a-zA-Z0-9._-]+)==([^\s,]+)", dep_str.strip())
    if match:
        return match.group(1).lower(), match.group(2)
    return dep_str.strip().lower(), None


def check_vulnerabilities(dependencies: List[Dict[str, str]], source_file: str = "requirements.txt") -> List[Dict]:
    """
    Запрашивает уязвимости в OSV API и возвращает список issue.
    """
    if not dependencies:
        return []

    queries = []
    for dep in dependencies:
        queries.append({
            "version": dep["version"],
            "package": {
                "name": dep["name"],
                "ecosystem": "PyPI"
            }
        })

    try:
        response = requests.post(OSV_API_URL, json={"queries": queries}, timeout=10)
        response.raise_for_status()
        results = response.json().get("results", [])
    except Exception as e:
        print(f"⚠️  Failed to query OSV API: {e}", file=sys.stderr)
        return []

    issues = []
    for i, result in enumerate(results):
        if "vulns" in result:
            dep = dependencies[i]
            for vuln in result["vulns"]:
                details_url = f"https://osv.dev/{vuln['id']}"
                issues.append({
                    "type": "vulnerable_dependency",
                    "description": f"{dep['name']}=={dep['version']} has known vulnerability: {vuln['id']}",
                    "severity": "high",
                    "line": 1,
                    "file": source_file,
                    "osv_id": vuln["id"],
                    "details_url": details_url
                })
    return issues