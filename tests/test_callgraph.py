"""Regression tests for the AST-based call graph / reachability analysis."""
from __future__ import annotations

from pathlib import Path

import pytest

from blastradius.callgraph import build_project_graph, all_users, find_reachable_users


def write(tmp_path: Path, name: str, content: str) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_flask_route_marks_reachable(tmp_path: Path):
    write(tmp_path, "app.py", """
from flask import Flask
import requests

app = Flask(__name__)

@app.route("/fetch")
def fetch_url():
    return requests.get("http://example.com").text

def unused_helper():
    return requests.post("http://example.com/unused")
""")
    graph = build_project_graph(tmp_path)
    reachable = {fn.qualname for fn in find_reachable_users(graph, "requests")}
    users = {fn.qualname for fn in all_users(graph, "requests")}

    assert users == {"app.py:fetch_url", "app.py:unused_helper"}
    assert reachable == {"app.py:fetch_url"}


def test_main_guard_block_is_entrypoint(tmp_path: Path):
    write(tmp_path, "run.py", """
import risky_pkg

def helper():
    return risky_pkg.do_thing()

if __name__ == "__main__":
    helper()
""")
    graph = build_project_graph(tmp_path)
    reachable = {fn.qualname for fn in find_reachable_users(graph, "risky_pkg")}
    assert reachable == {"run.py:helper"}


def test_never_called_function_is_not_reachable(tmp_path: Path):
    write(tmp_path, "lib.py", """
import risky_pkg

def dead_code():
    return risky_pkg.do_thing()
""")
    graph = build_project_graph(tmp_path)
    assert all_users(graph, "risky_pkg")
    assert find_reachable_users(graph, "risky_pkg") == []


def test_argparse_usage_flags_entrypoint(tmp_path: Path):
    write(tmp_path, "cli.py", """
from argparse import ArgumentParser
import risky_pkg

def init(argv):
    ap = ArgumentParser()
    return risky_pkg.do_thing()
""")
    graph = build_project_graph(tmp_path)
    fn = graph.funcs["cli.py:init"]
    assert fn.is_entrypoint
    reachable = {fn.qualname for fn in find_reachable_users(graph, "risky_pkg")}
    assert reachable == {"cli.py:init"}


def test_same_named_methods_in_different_classes_do_not_collide(tmp_path: Path):
    write(tmp_path, "views.py", """
import risky_pkg

class SafeView:
    def get(self):
        return "ok"

class RiskyView:
    @app.route("/risky")
    def get(self):
        return risky_pkg.do_thing()
""")
    graph = build_project_graph(tmp_path)
    # both methods keep distinct qualnames instead of merging into one "get" node
    assert "views.py:SafeView.get" in graph.funcs
    assert "views.py:RiskyView.get" in graph.funcs
    reachable = {fn.qualname for fn in find_reachable_users(graph, "risky_pkg")}
    assert reachable == {"views.py:RiskyView.get"}


def test_call_resolution_prefers_same_file_over_cross_file_collision(tmp_path: Path):
    # two files both define a function named `handle`; only file_a's `handle`
    # is actually called by file_a's entrypoint. file_b's same-named `handle`
    # (which uses risky_pkg) must NOT be pulled in as a false positive.
    write(tmp_path, "file_a.py", """
def handle():
    return "safe"

@app.route("/a")
def entry_a():
    return handle()
""")
    write(tmp_path, "file_b.py", """
import risky_pkg

def handle():
    return risky_pkg.do_thing()
""")
    graph = build_project_graph(tmp_path)
    reachable = {fn.qualname for fn in find_reachable_users(graph, "risky_pkg")}
    assert reachable == set(), (
        "cross-file bare-name collision caused a false-positive reachability claim"
    )


def test_syntax_error_file_is_skipped_not_fatal(tmp_path: Path):
    write(tmp_path, "broken.py", "def f(:\n    pass")
    write(tmp_path, "ok.py", """
@app.route("/x")
def entry():
    return 1
""")
    graph = build_project_graph(tmp_path)
    assert "ok.py:entry" in graph.funcs
    assert not any(qn.startswith("broken.py") for qn in graph.funcs)
