# scanner/dependency_check.py

import re
import sys
from pathlib import Path
from typing import List, Dict
import requests

# OSV API endpoint для запроса по пакетам
OSV_API_URL = "https://osv.dev/api/querybatch"

def parse_requirements(requirements_path: Path) -> List[Dict[str, str]]:
    """
    Парсит requirements.txt и возвращает список: [{"name": "django", "version": "3.2.0"}, ...]
    Поддерживает форматы:
      django==3.2.0
      requests>=2.25.0
      flask
    """
    if not requirements_path.exists():
        return []

    deps = []
    with open(requirements_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Убираем комментарии после #
            line = line.split("#")[0].strip()

            # Извлекаем имя и версию (поддержка ==, >=, <=, ~= и т.д.)
            match = re.match(r"^([a-zA-Z0-9._-]+)([<>=!~].*)?$", line)
            if not match:
                continue

            name = match.group(1).lower()
            version_spec = match.group(2) or ""

            # Извлекаем конкретную версию, если есть ==
            version = None
            if "==" in version_spec:
                version = version_spec.split("==")[1].split(",")[0].strip()
            elif version_spec == "":
                # Без версии — пропускаем (не можем проверить CVE)
                continue
            else:
                # Для >=, <= и т.д. — пока не поддерживаем (можно расширить позже)
                continue

            if version:
                deps.append({"name": name, "version": version})

    return deps


def check_vulnerabilities(dependencies: List[Dict[str, str]]) -> List[Dict]:
    """
    Отправляет запрос в OSV API, и возвращает список уязвимостей.
    """
    if not dependencies:
        print("🔍 No dependencies with pinned versions found in requirements.txt", file=sys.stderr)
        return []

    # Формируем запрос в формате OSV batch query
    queries = []
    dep_map = {}  # чтобы потом маппить ответы обратно
    for dep in dependencies:
        pkg_key = f"{dep['name']}@{dep['version']}"
        queries.append({
            "version": dep["version"],
            "package": {
                "name": dep["name"],
                "ecosystem": "PyPI"
            }
        })
        dep_map[pkg_key] = dep

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
                issues.append({
                    "type": "vulnerable_dependency",
                    "description": f"{dep['name']}=={dep['version']} has known vulnerability: {vuln['id']}",
                    "severity": "high",  # OSV не всегда даёт severity — можно улучшить позже
                    "line": 1,  # в requirements.txt строка не привязана — условно 1
                    "file": "requirements.txt",
                    "osv_id": vuln["id"],
                    "details_url": f"https://osv.dev/{vuln['id']}"
                })
    return issues