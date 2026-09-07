"""Query OSV.dev for known vulnerabilities. Results are cached to disk
(24h TTL by default) since a scan can mean 100+ sequential requests.
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


def _cache_key(package: str, version: str | None, ecosystem: str = "PyPI") -> str:
    raw = f"{ecosystem}:{package}@{version or 'unknown'}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _read_cache(cache_dir: Path, package: str, version: str | None, ecosystem: str, ttl: float) -> list[Vulnerability] | None:
    path = cache_dir / f"{_cache_key(package, version, ecosystem)}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    # >= not >: with ttl=0 this must always be "expired" regardless of clock
    # resolution (time.time() on Windows can return the same value across
    # two calls a few ms apart, which made age == 0 == ttl slip through)
    if time.time() - data.get("cached_at", 0) >= ttl:
        return None
    try:
        return [Vulnerability(**v) for v in data["vulns"]]
    except (KeyError, TypeError):
        return None


def _write_cache(cache_dir: Path, package: str, version: str | None, ecosystem: str, vulns: list[Vulnerability]) -> None:
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = cache_dir / f"{_cache_key(package, version, ecosystem)}.json"
        payload = {"package": package, "version": version, "ecosystem": ecosystem, "cached_at": time.time(),
                   "vulns": [asdict(v) for v in vulns]}
        path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass  # caching is best-effort


def _retry_after_seconds(resp: requests.Response) -> float | None:
    """Parse a 429/503 response's Retry-After header (seconds or HTTP-date)."""
    header = resp.headers.get("Retry-After")
    if not header:
        return None
    try:
        return max(0.0, float(header))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(header)
        if dt is not None:
            import datetime
            now = datetime.datetime.now(dt.tzinfo or datetime.timezone.utc)
            return max(0.0, (dt - now).total_seconds())
    except (TypeError, ValueError):
        pass
    return None


def _query_osv(package: str, version: str | None, ecosystem: str = "PyPI") -> list[Vulnerability]:
    payload: dict = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version

    last_exc: Exception | None = None
    resp = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = requests.post(OSV_QUERY_URL, json=payload, timeout=10)
            resp.raise_for_status()  # -> HTTPError on any 4xx/5xx, classified as retryable or not below
            break
        except requests.RequestException as exc:
            last_exc = exc
            is_response_error = isinstance(exc, requests.HTTPError) and exc.response is not None
            status = exc.response.status_code if is_response_error else None
            retryable = status is None or status == 429 or status >= 500
            if not retryable:
                raise RuntimeError(f"OSV query failed for {package}: {exc}") from exc
            if attempt < _MAX_RETRIES:
                wait = None
                if status == 429 and exc.response is not None:
                    wait = _retry_after_seconds(exc.response)
                if wait is None:
                    wait = _RETRY_BACKOFF_SECONDS * (2 ** attempt)
                time.sleep(wait)
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
    ecosystem: str = "PyPI",
    use_cache: bool = True,
    cache_dir: Path | None = None,
    cache_ttl: float = DEFAULT_CACHE_TTL_SECONDS,
) -> list[Vulnerability]:
    """Return known OSV vulnerabilities for a package at a given version.
    `ecosystem` is an OSV.dev ecosystem string ("PyPI" or "npm"). If
    version is None, queries unpinned (see report.py's version_unknown
    handling, which caps severity for that case).
    """
    cache_dir = cache_dir or _default_cache_dir()

    if use_cache:
        cached = _read_cache(cache_dir, package, version, ecosystem, cache_ttl)
        if cached is not None:
            return cached

    vulns = _query_osv(package, version, ecosystem)

    if use_cache:
        _write_cache(cache_dir, package, version, ecosystem, vulns)

    return vulns
