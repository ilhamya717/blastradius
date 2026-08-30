"""Discover project dependencies and their installed versions."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

try:
    from importlib import metadata as importlib_metadata
except ImportError:  # pragma: no cover
    import importlib_metadata  # type: ignore


@dataclass(frozen=True)
class Dependency:
    name: str          # distribution/package name, e.g. "requests" or "express"
    version: str | None  # installed/pinned version, if resolvable
    ecosystem: str = "PyPI"  # OSV.dev ecosystem string: "PyPI" or "npm"

    @property
    def top_level_modules(self) -> list[str]:
        """Guess the importable module name(s) for this distribution."""
        if self.ecosystem == "npm":
            # a JS/TS import/require specifier IS the package name, verbatim
            # (including scopes like "@org/pkg" and dots like "lodash.get")
            return [self.name]
        try:
            dist = importlib_metadata.distribution(self.name)
        except importlib_metadata.PackageNotFoundError:
            return [self.name.replace("-", "_")]
        try:
            text = dist.read_text("top_level.txt")
        except Exception:
            text = None
        if text:
            return [line.strip() for line in text.splitlines() if line.strip()]
        return [self.name.replace("-", "_")]


_REQ_LINE_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(==\s*([A-Za-z0-9.!+*_-]+))?")


def _parse_requirements_txt(path: Path) -> dict[str, str | None]:
    """Return {name: pinned_version_or_None}, honoring '==' pins when present."""
    pins: dict[str, str | None] = {}
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.split("#", 1)[0].strip()  # strip trailing '# via ...' comments
        if not line or line.startswith("-"):
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            pins[m.group(1)] = m.group(3)
    return pins


def _parse_pyproject_toml(path: Path) -> list[str]:
    try:
        import tomllib
    except ImportError:  # Python < 3.11
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return []
    data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
    names = []
    deps = data.get("project", {}).get("dependencies", [])
    for dep in deps:
        m = _REQ_LINE_RE.match(dep.strip())
        if m:
            names.append(m.group(1))
    return names


def discover_dependencies(project_root: Path) -> list[Dependency]:
    """Find declared dependencies. Prefers a requirements.txt '==' pin (the
    version the project actually declares/ships with) over whatever happens
    to be installed in the current environment -- those can differ a lot.
    """
    pinned: dict[str, str | None] = {}

    req_txt = project_root / "requirements.txt"
    if req_txt.exists():
        pinned.update(_parse_requirements_txt(req_txt))

    pyproject = project_root / "pyproject.toml"
    if pyproject.exists():
        for name in _parse_pyproject_toml(pyproject):
            pinned.setdefault(name, None)

    deps = []
    for name in sorted(pinned):
        version = pinned[name]
        if version is None:
            try:
                version = importlib_metadata.version(name)
            except importlib_metadata.PackageNotFoundError:
                pass
        deps.append(Dependency(name=name, version=version))
    return deps


_NPM_VERSION_RANGE_PREFIX = re.compile(r"^[\^~>=<\s]+")


def discover_js_dependencies(project_root: Path) -> list[Dependency]:
    """Parse package.json's dependencies/devDependencies. Prefers a locked
    exact version from package-lock.json/npm-shrinkwrap.json over
    package.json's range (e.g. "^4.18.0").
    """
    pkg_json = project_root / "package.json"
    if not pkg_json.exists():
        return []
    try:
        manifest = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return []

    ranges: dict[str, str] = {}
    for section in ("dependencies", "devDependencies"):
        ranges.update(manifest.get(section) or {})

    locked: dict[str, str] = {}
    for lockfile in ("package-lock.json", "npm-shrinkwrap.json"):
        lock_path = project_root / lockfile
        if not lock_path.exists():
            continue
        try:
            lock_data = json.loads(lock_path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            continue
        # npm lockfile v2/v3: packages["node_modules/<name>"].version
        for key, info in (lock_data.get("packages") or {}).items():
            if key.startswith("node_modules/") and isinstance(info, dict) and info.get("version"):
                locked.setdefault(key[len("node_modules/"):], info["version"])
        # lockfile v1 fallback
        for name, info in (lock_data.get("dependencies") or {}).items():
            if isinstance(info, dict) and info.get("version"):
                locked.setdefault(name, info["version"])
        break  # first lockfile found wins

    deps = []
    for name in sorted(ranges):
        version = locked.get(name) or _NPM_VERSION_RANGE_PREFIX.sub("", ranges[name]).strip() or None
        # a bare range (no lockfile) isn't a confirmed version -- only trust
        # it if it looks like an exact pin (no remaining range operators)
        if version and not re.fullmatch(r"[\w.\-+]+", version):
            version = None
        deps.append(Dependency(name=name, version=version, ecosystem="npm"))
    return deps
