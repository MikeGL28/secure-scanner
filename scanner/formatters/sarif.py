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
                    "informationUri": "https://github.com/yourname/secure-scanner",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    # Уникальные правила
    rule_ids = set(issue["type"] for issue in issues)

    for rule_id in rule_ids:
        sarif["runs"][0]["tool"]["driver"]["rules"].append({
            "id": rule_id,
            "shortDescription": {"text": rule_id.replace("_", " ").title()},
            "helpUri": f"https://github.com/yourname/secure-scanner/blob/main/docs/rules/{rule_id}.md"
        })

    for issue in issues:
        sarif["runs"][0]["results"].append({
            "ruleId": issue["type"],
            "level": _map_severity_to_sarif_level(issue["severity"]),
            "message": {"text": issue["description"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": issue["file"]},
                    "region": {"startLine": issue["line"]}
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