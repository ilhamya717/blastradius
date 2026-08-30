"""Discover project dependencies and their installed versions."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

try:
    from importlib import metadata as importlib_metadata
except ImportError:  # pragma: no cover
    import importlib_metadata  # type: ignore


@dataclass(frozen=True)
class Dependency:
    name: str          # PyPI distribution name, e.g. "requests"
    version: str | None  # installed version, if resolvable

    @property
    def top_level_modules(self) -> list[str]:
        """Guess the importable module name(s) for this distribution."""
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
