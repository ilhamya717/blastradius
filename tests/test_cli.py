"""Tests for CLI-level project-root discovery (monorepo auto-detection)."""
from __future__ import annotations

from pathlib import Path

from blastradius.cli import _find_manifest_roots


def test_root_with_manifest_is_found(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.6.0\n", encoding="utf-8")
    assert _find_manifest_roots(tmp_path) == [tmp_path]


def test_monorepo_backend_frontend_split_is_auto_discovered(tmp_path: Path):
    """Regression: a real-world case where package.json lives in backend/
    and frontend/ subdirectories, not the project root -- scanning the
    root used to silently find nothing and report a false 'clean'."""
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "README.md").write_text("# hi\n", encoding="utf-8")

    roots = _find_manifest_roots(tmp_path)
    assert set(roots) == {tmp_path / "backend", tmp_path / "frontend"}


def test_no_manifest_anywhere_returns_empty(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print(1)\n", encoding="utf-8")
    assert _find_manifest_roots(tmp_path) == []


def test_skips_node_modules_and_venv(tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "pyproject.toml").write_text("", encoding="utf-8")
    assert _find_manifest_roots(tmp_path) == []


def test_root_manifest_and_subdirectory_manifest_both_included(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.6.0\n", encoding="utf-8")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "package.json").write_text("{}", encoding="utf-8")

    roots = _find_manifest_roots(tmp_path)
    assert set(roots) == {tmp_path, tmp_path / "frontend"}
