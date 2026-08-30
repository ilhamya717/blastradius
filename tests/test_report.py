"""Tests for severity classification logic -- the core value proposition."""
from __future__ import annotations

from blastradius.report import BlastRadiusEntry
from blastradius.scanner import Dependency
from blastradius.vulndb import Vulnerability


def make_entry(*, version, vulns, total_users, reachable_users):
    return BlastRadiusEntry(
        dependency=Dependency(name="pkg", version=version),
        module="pkg",
        vulns=vulns,
        total_users=total_users,
        reachable_users=reachable_users,
    )


FAKE_VULN = [Vulnerability(id="GHSA-xxxx", summary="test", severity=None, aliases=[])]


def test_no_vulns_is_severity_none():
    e = make_entry(version="1.0", vulns=[], total_users=5, reachable_users=["a"])
    assert e.severity == "none"


def test_reachable_and_versioned_is_critical():
    e = make_entry(version="1.0", vulns=FAKE_VULN, total_users=1, reachable_users=["mod.py:f"])
    assert e.severity == "critical"


def test_used_but_not_reachable_is_moderate():
    e = make_entry(version="1.0", vulns=FAKE_VULN, total_users=2, reachable_users=[])
    assert e.severity == "moderate"


def test_declared_but_unused_is_low():
    e = make_entry(version="1.0", vulns=FAKE_VULN, total_users=0, reachable_users=[])
    assert e.severity == "low"


def test_unknown_version_never_reaches_critical_even_if_reachable():
    """Regression: unpinned OSV queries match vulns across all historical
    versions, so reachability alone must not be allowed to imply CRITICAL
    when we can't confirm the actual version in use."""
    e = make_entry(version=None, vulns=FAKE_VULN, total_users=1, reachable_users=["mod.py:f"])
    assert e.severity == "moderate"
    assert e.version_unknown is True


def test_unknown_version_and_unused_is_low():
    e = make_entry(version=None, vulns=FAKE_VULN, total_users=0, reachable_users=[])
    assert e.severity == "low"
