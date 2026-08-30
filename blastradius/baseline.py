"""Baseline diffing for CI: fail only on *new* risk, not everything every run.

A baseline is a JSON snapshot of the last-accepted report, keyed by
package. Diffing against it surfaces: a newly flagged package, a
newly-disclosed CVE, a severity escalation, or a package that dropped
out (upgraded/removed -- good news).
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .report import BlastRadiusEntry

_SEVERITY_RANK = {"none": 0, "low": 1, "moderate": 2, "critical": 3}


def build_baseline(entries: list[BlastRadiusEntry]) -> dict:
    """Snapshot the current report into a baseline-shaped dict."""
    packages = {}
    for e in entries:
        if e.severity == "none":
            continue
        key = f"{e.dependency.name}:{e.module}"
        packages[key] = {
            "package": e.dependency.name,
            "module": e.module,
            "version": e.dependency.version,
            "severity": e.severity,
            "vuln_ids": sorted(v.id for v in e.vulns),
        }
    return {"schema": 1, "packages": packages}


def load_baseline(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_baseline(path: Path, baseline: dict) -> None:
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")


@dataclass
class BaselineDiff:
    new_packages: list[str] = field(default_factory=list)     # never seen before
    new_vulns: dict[str, list[str]] = field(default_factory=dict)   # pkg -> newly appeared CVE ids
    escalated: dict[str, tuple[str, str]] = field(default_factory=dict)  # pkg -> (old_sev, new_sev)
    resolved: list[str] = field(default_factory=list)          # was in baseline, gone now (good)

    @property
    def has_new_risk(self) -> bool:
        return bool(self.new_packages or self.new_vulns or self.escalated)

    def summary_lines(self) -> list[str]:
        lines = []
        for pkg in self.new_packages:
            lines.append(f"NEW: {pkg} is a newly-flagged finding (not in baseline)")
        for pkg, ids in self.new_vulns.items():
            lines.append(f"NEW CVEs: {pkg} gained {len(ids)} new advisory id(s): {', '.join(ids)}")
        for pkg, (old, new) in self.escalated.items():
            lines.append(f"ESCALATED: {pkg} severity {old} -> {new}")
        for pkg in self.resolved:
            lines.append(f"RESOLVED: {pkg} no longer flagged (fixed/upgraded/removed)")
        return lines


def diff_against_baseline(entries: list[BlastRadiusEntry], baseline: dict) -> BaselineDiff:
    current = build_baseline(entries)["packages"]
    old = baseline.get("packages", {})

    diff = BaselineDiff()
    for key, cur in current.items():
        if key not in old:
            diff.new_packages.append(key)
            continue
        prev = old[key]
        new_ids = sorted(set(cur["vuln_ids"]) - set(prev.get("vuln_ids", [])))
        if new_ids:
            diff.new_vulns[key] = new_ids
        old_rank = _SEVERITY_RANK.get(prev.get("severity", "none"), 0)
        new_rank = _SEVERITY_RANK.get(cur["severity"], 0)
        if new_rank > old_rank:
            diff.escalated[key] = (prev.get("severity", "none"), cur["severity"])

    for key in old:
        if key not in current:
            diff.resolved.append(key)

    return diff
