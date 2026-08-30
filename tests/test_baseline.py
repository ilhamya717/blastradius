"""Tests for baseline diffing: fail CI only on *new* risk, not old-and-accepted."""
from __future__ import annotations

from blastradius.baseline import build_baseline, diff_against_baseline
from blastradius.report import BlastRadiusEntry
from blastradius.scanner import Dependency
from blastradius.vulndb import Vulnerability


def entry(name, module, version, severity_inputs, vuln_ids):
    """severity_inputs: (total_users, reachable_users) to drive severity naturally."""
    total_users, reachable_users = severity_inputs
    vulns = [Vulnerability(id=vid, summary="x", severity=None, aliases=[]) for vid in vuln_ids]
    return BlastRadiusEntry(
        dependency=Dependency(name=name, version=version),
        module=module,
        vulns=vulns,
        total_users=total_users,
        reachable_users=reachable_users,
    )


def test_identical_report_has_no_diff():
    entries = [entry("aiohttp", "aiohttp", "3.5.3", (1, ["a.py:f"]), ["GHSA-1"])]
    baseline = build_baseline(entries)
    diff = diff_against_baseline(entries, baseline)
    assert not diff.has_new_risk
    assert diff.new_packages == []
    assert diff.new_vulns == {}
    assert diff.escalated == {}
    assert diff.resolved == []


def test_new_package_is_flagged():
    old = [entry("aiohttp", "aiohttp", "3.5.3", (1, ["a.py:f"]), ["GHSA-1"])]
    baseline = build_baseline(old)
    new = old + [entry("jinja2", "jinja2", "2.10", (1, ["a.py:g"]), ["GHSA-2"])]
    diff = diff_against_baseline(new, baseline)
    assert diff.has_new_risk
    assert "jinja2:jinja2" in diff.new_packages


def test_new_cve_on_existing_package_is_flagged():
    old = [entry("aiohttp", "aiohttp", "3.5.3", (1, ["a.py:f"]), ["GHSA-1"])]
    baseline = build_baseline(old)
    new = [entry("aiohttp", "aiohttp", "3.5.3", (1, ["a.py:f"]), ["GHSA-1", "GHSA-2"])]
    diff = diff_against_baseline(new, baseline)
    assert diff.has_new_risk
    assert diff.new_vulns["aiohttp:aiohttp"] == ["GHSA-2"]


def test_severity_escalation_is_flagged():
    # used but not reachable (moderate) -> now reachable (critical)
    old = [entry("aiohttp", "aiohttp", "3.5.3", (1, []), ["GHSA-1"])]
    baseline = build_baseline(old)
    new = [entry("aiohttp", "aiohttp", "3.5.3", (1, ["a.py:f"]), ["GHSA-1"])]
    diff = diff_against_baseline(new, baseline)
    assert diff.has_new_risk
    assert diff.escalated["aiohttp:aiohttp"] == ("moderate", "critical")


def test_resolved_package_does_not_count_as_new_risk():
    old = [entry("aiohttp", "aiohttp", "3.5.3", (1, ["a.py:f"]), ["GHSA-1"])]
    baseline = build_baseline(old)
    new: list[BlastRadiusEntry] = []  # upgraded away, no longer flagged
    diff = diff_against_baseline(new, baseline)
    assert not diff.has_new_risk
    assert diff.resolved == ["aiohttp:aiohttp"]


def test_severity_downgrade_is_not_flagged_as_new_risk():
    old = [entry("aiohttp", "aiohttp", "3.5.3", (1, ["a.py:f"]), ["GHSA-1"])]
    baseline = build_baseline(old)
    new = [entry("aiohttp", "aiohttp", "3.5.3", (1, []), ["GHSA-1"])]  # became unreachable
    diff = diff_against_baseline(new, baseline)
    assert not diff.has_new_risk
    assert diff.escalated == {}
