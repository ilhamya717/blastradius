"""Tests for the OSV.dev response cache."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from blastradius.vulndb import Vulnerability, query_vulnerabilities


def _fake_osv_response(vuln_ids):
    return {"vulns": [{"id": vid, "summary": "test", "aliases": []} for vid in vuln_ids]}


def test_second_call_hits_cache_not_network(tmp_path: Path):
    call_count = 0

    def fake_query(package, version):
        nonlocal call_count
        call_count += 1
        return [Vulnerability(id="GHSA-1", summary="x", severity=None, aliases=[])]

    with patch("blastradius.vulndb._query_osv", side_effect=fake_query):
        first = query_vulnerabilities("pkg", "1.0", cache_dir=tmp_path)
        second = query_vulnerabilities("pkg", "1.0", cache_dir=tmp_path)

    assert call_count == 1  # second call served from disk cache
    assert first == second
    assert first[0].id == "GHSA-1"


def test_no_cache_flag_always_hits_network(tmp_path: Path):
    call_count = 0

    def fake_query(package, version):
        nonlocal call_count
        call_count += 1
        return []

    with patch("blastradius.vulndb._query_osv", side_effect=fake_query):
        query_vulnerabilities("pkg", "1.0", use_cache=False, cache_dir=tmp_path)
        query_vulnerabilities("pkg", "1.0", use_cache=False, cache_dir=tmp_path)

    assert call_count == 2


def test_different_versions_have_independent_cache_entries(tmp_path: Path):
    responses = iter([
        [Vulnerability(id="GHSA-OLD", summary="x", severity=None, aliases=[])],
        [],  # newer version, no vulns
    ])

    def fake_query(package, version):
        return next(responses)

    with patch("blastradius.vulndb._query_osv", side_effect=fake_query):
        old = query_vulnerabilities("pkg", "1.0", cache_dir=tmp_path)
        new = query_vulnerabilities("pkg", "2.0", cache_dir=tmp_path)

    assert [v.id for v in old] == ["GHSA-OLD"]
    assert new == []


def test_expired_cache_entry_is_refetched(tmp_path: Path):
    call_count = 0

    def fake_query(package, version):
        nonlocal call_count
        call_count += 1
        return []

    with patch("blastradius.vulndb._query_osv", side_effect=fake_query):
        query_vulnerabilities("pkg", "1.0", cache_dir=tmp_path, cache_ttl=0)
        query_vulnerabilities("pkg", "1.0", cache_dir=tmp_path, cache_ttl=0)

    assert call_count == 2  # ttl=0 means every read is already "expired"


def test_corrupt_cache_file_falls_back_to_network(tmp_path: Path):
    from blastradius.vulndb import _cache_key
    cache_file = tmp_path / f"{_cache_key('pkg', '1.0')}.json"
    tmp_path.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("not valid json{{{", encoding="utf-8")

    def fake_query(package, version):
        return [Vulnerability(id="GHSA-FRESH", summary="x", severity=None, aliases=[])]

    with patch("blastradius.vulndb._query_osv", side_effect=fake_query):
        result = query_vulnerabilities("pkg", "1.0", cache_dir=tmp_path)

    assert result[0].id == "GHSA-FRESH"
