"""Tests for JS/TS support. These run the real Node.js helper (no mocking
the parser) -- skipped automatically if Node.js isn't on PATH, mirroring
how the CLI itself degrades gracefully rather than hard-failing.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from blastradius.callgraph import all_users, find_reachable_users

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not on PATH")


def write(tmp_path: Path, name: str, content: str) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")


def _build(tmp_path: Path):
    from blastradius.js_callgraph import build_js_project_graph
    return build_js_project_graph(tmp_path)


def test_express_route_marks_reachable(tmp_path: Path):
    write(tmp_path, "app.js", """
const express = require("express");
const risky = require("risky-pkg");

const app = express();

app.get("/x", function handler(req, res) {
  return risky.doThing();
});

function unusedHelper() {
  return risky.doThing();
}
""")
    graph = _build(tmp_path)
    users = {fn.qualname for fn in all_users(graph, "risky-pkg")}
    reachable = {fn.qualname for fn in find_reachable_users(graph, "risky-pkg")}

    assert "app.js:handler" in users
    assert "app.js:unusedHelper" in users
    # module-level `require("risky-pkg")` is itself a top-of-file use, and
    # app.js is a root file (it holds the entrypoint) -- so __module__
    # legitimately shows reachable too, same as the Python side's
    # `app = Flask(__name__)` case. unusedHelper must NOT be in this set.
    assert reachable == {"app.js:handler", "app.js:__module__"}


def test_commonjs_require_alias_tracked_inside_function_body(tmp_path: Path):
    """Regression: `const _ = require("lodash")` must make later `_.foo()`
    calls inside function bodies count as usage, not just the require()
    call site itself."""
    write(tmp_path, "app.js", """
const _ = require("lodash");

function handler() {
  return _.merge({}, {});
}

module.exports = handler;
handler();
""")
    graph = _build(tmp_path)
    users = {fn.qualname for fn in all_users(graph, "lodash")}
    assert "app.js:handler" in users


def test_inline_arrow_function_route_handler_is_entrypoint(tmp_path: Path):
    write(tmp_path, "app.js", """
const risky = require("risky-pkg");
app.post("/y", (req, res) => {
  return risky.doThing();
});
""")
    graph = _build(tmp_path)
    reachable = {fn.qualname for fn in find_reachable_users(graph, "risky-pkg")}
    handler_entries = [q for q in reachable if q != "app.js:__module__"]
    assert len(handler_entries) == 1
    assert graph.funcs[handler_entries[0]].entrypoint_reason == "inline route handler"


def test_never_registered_function_is_not_reachable(tmp_path: Path):
    write(tmp_path, "lib.js", """
const risky = require("risky-pkg");

function deadCode() {
  return risky.doThing();
}
""")
    graph = _build(tmp_path)
    assert all_users(graph, "risky-pkg")
    assert find_reachable_users(graph, "risky-pkg") == []


def test_relative_project_root_still_resolves_files(tmp_path: Path, monkeypatch):
    """Regression: build_js_project_graph must .resolve() its input --
    the Node subprocess runs with a fixed cwd, so a relative project_root
    used to silently produce an empty graph."""
    write(tmp_path, "app.js", """
app.get("/x", function handler() {
  return 1;
});
""")
    monkeypatch.chdir(tmp_path.parent)
    from blastradius.js_callgraph import build_js_project_graph
    graph = build_js_project_graph(Path(tmp_path.name))  # relative path
    assert any(fn.is_entrypoint for fn in graph.funcs.values())


def test_syntax_error_file_is_skipped_not_fatal(tmp_path: Path):
    write(tmp_path, "broken.js", "function( { this is not valid js at all !!")
    write(tmp_path, "ok.js", """
app.get("/x", function handler() {
  return 1;
});
""")
    graph = _build(tmp_path)
    assert any(fn.qualname == "ok.js:handler" for fn in graph.funcs.values())
    assert not any(fn.file == "broken.js" for fn in graph.funcs.values())
