# scanner/formatters/sarif.py

import json
from typing import List, Dict

def generate_sarif_report(issues: List[Dict], tool_name: str = "secure-scanner") -> Dict:
    """
    Генерирует отчёт в формате SARIF v2.1.0
    """
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": "0.1.0",
                    "informationUri": "https://github.com/MikeGL28/secure-scanner",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    # Уникальные ruleId из всех issue
    rule_ids = {issue["type"] for issue in issues if "type" in issue}

    for rule_id in rule_ids:
        # Формируем человекочитаемое описание
        short_desc = rule_id.replace("_", " ").title()
        # Исправленный helpUri — без лишних пробелов
        help_uri = f"https://github.com/MikeGL28/secure-scanner/blob/main/docs/rules/{rule_id}.md"

        sarif["runs"][0]["tool"]["driver"]["rules"].append({
            "id": rule_id,
            "shortDescription": {"text": short_desc},
            "helpUri": help_uri
        })

    for issue in issues:
        if "type" not in issue or "severity" not in issue:
            continue  # пропускаем некорректные записи

        sarif["runs"][0]["results"].append({
            "ruleId": issue["type"],
            "level": _map_severity_to_sarif_level(issue.get("severity", "note")),
            "message": {"text": issue.get("description", "No description")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": issue.get("file", "unknown")},
                    "region": {"startLine": issue.get("line", 1)}
                }
            }]
        })

    return sarif


def _map_severity_to_sarif_level(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note"
    }
    return mapping.get(severity.lower(), "note")