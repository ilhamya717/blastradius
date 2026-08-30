"""Query OSV.dev for known vulnerabilities affecting a PyPI package+version."""
from __future__ import annotations

from dataclasses import dataclass

import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


@dataclass
class Vulnerability:
    id: str
    summary: str
    severity: str | None
    aliases: list[str]


def query_vulnerabilities(package: str, version: str | None) -> list[Vulnerability]:
    """Return known OSV vulnerabilities for a PyPI package at a given version.

    If version is None, queries without a version pin (broader match).
    """
    payload: dict = {"package": {"name": package, "ecosystem": "PyPI"}}
    if version:
        payload["version"] = version

    try:
        resp = requests.post(OSV_QUERY_URL, json=payload, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"OSV query failed for {package}: {exc}") from exc

    data = resp.json()
    vulns = []
    for entry in data.get("vulns", []):
        severity = None
        sev_list = entry.get("severity") or []
        if sev_list:
            severity = sev_list[0].get("score")
        summary = entry.get("summary") or entry.get("details", "")[:120] or "(no summary)"
        vulns.append(
            Vulnerability(
                id=entry.get("id", "UNKNOWN"),
                summary=summary,
                severity=severity,
                aliases=entry.get("aliases", []),
            )
        )
    return vulns
