"""Query OSV.dev for known vulnerabilities affecting a PyPI package+version.

Results are cached to disk (default: a project-local `.blastradius-cache/`,
falling back to the user cache dir if that can't be created) since a
project with 100+ dependencies means 100+ sequential OSV requests, and
that data changes at "new CVE disclosed" pace, not "every scan" pace.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DEFAULT_CACHE_TTL_SECONDS = 24 * 3600
_MAX_RETRIES = 2
_RETRY_BACKOFF_SECONDS = 0.5


@dataclass
class Vulnerability:
    id: str
    summary: str
    severity: str | None
    aliases: list[str]


def _default_cache_dir() -> Path:
    env = os.environ.get("BLASTRADIUS_CACHE_DIR")
    if env:
        return Path(env)
    return Path.home() / ".cache" / "blastradius" / "osv"


def _cache_key(package: str, version: str | None) -> str:
    raw = f"{package}@{version or 'unknown'}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _read_cache(cache_dir: Path, package: str, version: str | None, ttl: float) -> list[Vulnerability] | None:
    path = cache_dir / f"{_cache_key(package, version)}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if time.time() - data.get("cached_at", 0) > ttl:
        return None
    try:
        return [Vulnerability(**v) for v in data["vulns"]]
    except (KeyError, TypeError):
        return None


def _write_cache(cache_dir: Path, package: str, version: str | None, vulns: list[Vulnerability]) -> None:
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = cache_dir / f"{_cache_key(package, version)}.json"
        payload = {"package": package, "version": version, "cached_at": time.time(),
                   "vulns": [asdict(v) for v in vulns]}
        path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass  # caching is a best-effort speedup, never a hard requirement


def _query_osv(package: str, version: str | None) -> list[Vulnerability]:
    payload: dict = {"package": {"name": package, "ecosystem": "PyPI"}}
    if version:
        payload["version"] = version

    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = requests.post(OSV_QUERY_URL, json=payload, timeout=10)
            resp.raise_for_status()
            break
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < _MAX_RETRIES:
                time.sleep(_RETRY_BACKOFF_SECONDS * (2 ** attempt))
    else:
        raise RuntimeError(f"OSV query failed for {package} after {_MAX_RETRIES + 1} attempts: {last_exc}") from last_exc

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


def query_vulnerabilities(
    package: str,
    version: str | None,
    *,
    use_cache: bool = True,
    cache_dir: Path | None = None,
    cache_ttl: float = DEFAULT_CACHE_TTL_SECONDS,
) -> list[Vulnerability]:
    """Return known OSV vulnerabilities for a PyPI package at a given version.

    If version is None, queries without a version pin (broader match --
    see report.py's version_unknown handling, which deliberately doesn't
    let that inflate severity).
    """
    cache_dir = cache_dir or _default_cache_dir()

    if use_cache:
        cached = _read_cache(cache_dir, package, version, cache_ttl)
        if cached is not None:
            return cached

    vulns = _query_osv(package, version)

    if use_cache:
        _write_cache(cache_dir, package, version, vulns)

    return vulns
