"""Tests for requirements.txt parsing and version resolution."""
from __future__ import annotations

from pathlib import Path

from blastradius.scanner import discover_dependencies


def test_prefers_pinned_version_over_installed(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.6.0\n"
        "flask==2.0.0  # some comment\n"
        "attrs==18.2.0             # via aiohttp\n",
        encoding="utf-8",
    )
    deps = discover_dependencies(tmp_path)
    by_name = {d.name: d.version for d in deps}
    assert by_name["requests"] == "2.6.0"
    assert by_name["flask"] == "2.0.0"
    assert by_name["attrs"] == "18.2.0"


def test_unpinned_requirement_has_none_or_installed_version(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("some-nonexistent-package-xyz\n", encoding="utf-8")
    deps = discover_dependencies(tmp_path)
    assert deps[0].name == "some-nonexistent-package-xyz"
    assert deps[0].version is None


def test_ignores_comment_and_blank_lines(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text(
        "# a comment\n\nrequests==2.6.0\n-e .\n", encoding="utf-8"
    )
    deps = discover_dependencies(tmp_path)
    assert [d.name for d in deps] == ["requests"]
