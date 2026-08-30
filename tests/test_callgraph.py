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


def test_module_level_usage_in_entrypoint_file_is_reachable(tmp_path: Path):
    """Regression: `app = Flask(__name__)` at top of file was previously
    invisible to usage tracking entirely (only function bodies were scanned)."""
    write(tmp_path, "app.py", """
from flask import Flask

app = Flask(__name__)

@app.route("/ping")
def ping():
    return "pong"
""")
    graph = build_project_graph(tmp_path)
    users = all_users(graph, "flask")
    assert any(fn.is_module_scope for fn in users)
    reachable = find_reachable_users(graph, "flask")
    assert any(fn.is_module_scope and fn.file == "app.py" for fn in reachable)


def test_module_level_usage_reachable_via_import_chain(tmp_path: Path):
    """A file with no entrypoint of its own is still reachable if it's
    imported (directly or transitively) by a file that has one."""
    write(tmp_path, "main.py", """
from lib import helper

@app.route("/x")
def entry():
    return helper()
""")
    write(tmp_path, "lib.py", """
import risky_pkg

CLIENT = risky_pkg.Client()  # module-level side effect

def helper():
    return "ok"
""")
    graph = build_project_graph(tmp_path)
    reachable = find_reachable_users(graph, "risky_pkg")
    assert any(fn.is_module_scope and fn.file == "lib.py" for fn in reachable)


def test_module_level_usage_in_never_imported_file_is_not_reachable(tmp_path: Path):
    write(tmp_path, "main.py", """
@app.route("/x")
def entry():
    return "ok"
""")
    write(tmp_path, "orphan.py", """
import risky_pkg

CLIENT = risky_pkg.Client()
""")
    graph = build_project_graph(tmp_path)
    assert all_users(graph, "risky_pkg")  # it's used...
    assert find_reachable_users(graph, "risky_pkg") == []  # ...but orphan.py is never imported


def test_blueprint_style_decorator_is_entrypoint(tmp_path: Path):
    """@bp.route(...) on a Flask Blueprint instance -- attr-based matching
    means the object name (bp, api, router, ...) never mattered, but confirm
    it explicitly since this was flagged as a suspected gap."""
    write(tmp_path, "views.py", """
import risky_pkg

@bp.route("/x")
def handler():
    return risky_pkg.do_thing()
""")
    graph = build_project_graph(tmp_path)
    fn = graph.funcs["views.py:handler"]
    assert fn.is_entrypoint
    reachable = {f.qualname for f in find_reachable_users(graph, "risky_pkg")}
    assert reachable == {"views.py:handler"}


def test_django_class_based_view_method_is_entrypoint_without_decorator(tmp_path: Path):
    write(tmp_path, "views.py", """
from django.views import View
import risky_pkg

class MyView(View):
    def get(self, request):
        return risky_pkg.do_thing()

    def helper_not_a_verb(self):
        return risky_pkg.do_thing()
""")
    graph = build_project_graph(tmp_path)
    get_fn = graph.funcs["views.py:MyView.get"]
    assert get_fn.is_entrypoint
    assert "class-based view" in get_fn.entrypoint_reason

    helper_fn = graph.funcs["views.py:MyView.helper_not_a_verb"]
    assert not helper_fn.is_entrypoint  # non-HTTP-verb method stays plain


def test_drf_viewset_subclass_via_custom_base_is_entrypoint(tmp_path: Path):
    """A project-local base like `class BaseAPIView(APIView)` should still
    count for its own subclasses (suffix-based match, not exact-name)."""
    write(tmp_path, "views.py", """
class BaseAPIView(APIView):
    pass

class UserView(BaseAPIView):
    def post(self, request):
        return risky_pkg.do_thing()
""")
    graph = build_project_graph(tmp_path)
    assert graph.funcs["views.py:UserView.post"].is_entrypoint


def test_flask_add_url_rule_marks_referenced_view_as_entrypoint(tmp_path: Path):
    write(tmp_path, "app.py", """
import risky_pkg

def my_view():
    return risky_pkg.do_thing()

app.add_url_rule("/x", view_func=my_view)
""")
    graph = build_project_graph(tmp_path)
    fn = graph.funcs["app.py:my_view"]
    assert fn.is_entrypoint
    reachable = {f.qualname for f in find_reachable_users(graph, "risky_pkg")}
    assert reachable == {"app.py:my_view"}


def test_django_urlpatterns_path_marks_cross_file_view_as_entrypoint(tmp_path: Path):
    write(tmp_path, "views.py", """
import risky_pkg

def index(request):
    return risky_pkg.do_thing()
""")
    write(tmp_path, "urls.py", """
from django.urls import path
from . import views

urlpatterns = [
    path("", views.index),
]
""")
    graph = build_project_graph(tmp_path)
    fn = graph.funcs["views.py:index"]
    assert fn.is_entrypoint
    assert fn.entrypoint_reason == "referenced in a URL/route registration call"
    reachable = {f.qualname for f in find_reachable_users(graph, "risky_pkg")}
    assert reachable == {"views.py:index"}


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
