"""Tests for the OSV.dev response cache and HTTP retry/rate-limit handling."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import requests

from blastradius.vulndb import Vulnerability, _query_osv, query_vulnerabilities


def _fake_osv_response(vuln_ids):
    return {"vulns": [{"id": vid, "summary": "test", "aliases": []} for vid in vuln_ids]}


class _FakeResponse:
    def __init__(self, status_code, headers=None, json_data=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._json_data = json_data if json_data is not None else {"vulns": []}

    def raise_for_status(self):
        if self.status_code >= 400:
            err = requests.HTTPError(f"{self.status_code} error")
            err.response = self
            raise err

    def json(self):
        return self._json_data


def test_second_call_hits_cache_not_network(tmp_path: Path):
    call_count = 0

    def fake_query(package, version, ecosystem="PyPI"):
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

    def fake_query(package, version, ecosystem="PyPI"):
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

    def fake_query(package, version, ecosystem="PyPI"):
        return next(responses)

    with patch("blastradius.vulndb._query_osv", side_effect=fake_query):
        old = query_vulnerabilities("pkg", "1.0", cache_dir=tmp_path)
        new = query_vulnerabilities("pkg", "2.0", cache_dir=tmp_path)

    assert [v.id for v in old] == ["GHSA-OLD"]
    assert new == []


def test_expired_cache_entry_is_refetched(tmp_path: Path):
    call_count = 0

    def fake_query(package, version, ecosystem="PyPI"):
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

    def fake_query(package, version, ecosystem="PyPI"):
        return [Vulnerability(id="GHSA-FRESH", summary="x", severity=None, aliases=[])]

    with patch("blastradius.vulndb._query_osv", side_effect=fake_query):
        result = query_vulnerabilities("pkg", "1.0", cache_dir=tmp_path)

    assert result[0].id == "GHSA-FRESH"


def test_429_respects_retry_after_header(monkeypatch):
    responses = [
        _FakeResponse(429, headers={"Retry-After": "2"}),
        _FakeResponse(200, json_data=_fake_osv_response(["GHSA-1"])),
    ]
    sleeps: list[float] = []
    monkeypatch.setattr("blastradius.vulndb.time.sleep", lambda s: sleeps.append(s))

    with patch("blastradius.vulndb.requests.post", side_effect=responses):
        result = _query_osv("pkg", "1.0")

    assert [v.id for v in result] == ["GHSA-1"]
    assert sleeps == [2.0]  # honored Retry-After, not the generic exponential backoff


def test_429_without_retry_after_falls_back_to_exponential_backoff(monkeypatch):
    responses = [
        _FakeResponse(429),  # no Retry-After header
        _FakeResponse(200, json_data=_fake_osv_response([])),
    ]
    sleeps: list[float] = []
    monkeypatch.setattr("blastradius.vulndb.time.sleep", lambda s: sleeps.append(s))

    with patch("blastradius.vulndb.requests.post", side_effect=responses):
        _query_osv("pkg", "1.0")

    assert sleeps == [0.5]  # first backoff step


def test_5xx_is_retried(monkeypatch):
    responses = [
        _FakeResponse(503),
        _FakeResponse(200, json_data=_fake_osv_response([])),
    ]
    monkeypatch.setattr("blastradius.vulndb.time.sleep", lambda s: None)

    with patch("blastradius.vulndb.requests.post", side_effect=responses):
        result = _query_osv("pkg", "1.0")

    assert result == []


def test_4xx_client_error_is_not_retried(monkeypatch):
    call_count = 0

    def fake_post(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return _FakeResponse(400)

    monkeypatch.setattr("blastradius.vulndb.time.sleep", lambda s: None)

    with patch("blastradius.vulndb.requests.post", side_effect=fake_post):
        try:
            _query_osv("pkg", "1.0")
            assert False, "expected RuntimeError"
        except RuntimeError:
            pass

    assert call_count == 1  # no retry wasted on a request that will never succeed


def test_exhausting_all_retries_raises_with_context(monkeypatch):
    monkeypatch.setattr("blastradius.vulndb.time.sleep", lambda s: None)

    with patch("blastradius.vulndb.requests.post", side_effect=lambda *a, **k: _FakeResponse(503)):
        try:
            _query_osv("pkg", "1.0")
            assert False, "expected RuntimeError"
        except RuntimeError as exc:
            assert "pkg" in str(exc)
