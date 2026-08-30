"""Heuristic static analysis: which functions use which dependencies, and
whether they're reachable from an entrypoint. No type inference or code
execution -- a useful signal, not a sound one.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

# Test files never count as entrypoints (still parsed for calls/usage) --
# @patch is unittest.mock, not an HTTP PATCH route, etc.
_TEST_FILE_RE = re.compile(r"(^|[\\/])tests?[\\/]|(^|[\\/])test_[^\\/]*\.py$|_test\.py$", re.IGNORECASE)


def _is_test_file(rel_path: str) -> bool:
    return bool(_TEST_FILE_RE.search(rel_path))

ENTRYPOINT_DECORATORS = {
    "route", "get", "post", "put", "delete", "patch", "head", "options",  # Flask/FastAPI/Starlette
    "api_route", "websocket", "on_event", "middleware",                   # FastAPI
    "before_request", "after_request", "teardown_request", "errorhandler",  # Flask hooks
    "task", "command", "cli",                                            # Celery/Click
    "action",                                                            # DRF @action
}

# HTTP-verb-named methods on a class-based view are entrypoints with no
# decorator at all (Flask MethodView, Django View/APIView, DRF ViewSet).
HTTP_METHOD_NAMES = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
DRF_VIEWSET_ACTIONS = {"list", "retrieve", "create", "update", "partial_update", "destroy"}
CLASS_BASED_VIEW_METHODS = HTTP_METHOD_NAMES | DRF_VIEWSET_ACTIONS

# A call to one of these is a URL/route registration; any function or
# `module.func` argument is a view, decorated or not.
REGISTRATION_CALL_NAMES = {
    "add_url_rule", "add_api_route", "add_route",
    "add_get", "add_post", "add_put", "add_delete", "add_patch",
    "path", "re_path", "url",
}


@dataclass
class FuncNode:
    qualname: str          # "path/to/file.py:funcname" (or ":__module__")
    file: str
    lineno: int
    calls: set[str] = field(default_factory=set)         # bare names called
    uses_modules: set[str] = field(default_factory=set)  # top-level modules referenced
    is_entrypoint: bool = False
    entrypoint_reason: str | None = None
    is_module_scope: bool = False  # synthetic "top of file" node


@dataclass
class ProjectGraph:
    funcs: dict[str, FuncNode] = field(default_factory=dict)
    by_bare_name: dict[str, set[str]] = field(default_factory=dict)  # for call resolution
    file_imports: dict[str, set[str]] = field(default_factory=dict)  # local import graph
    _raw_imports: dict[str, list[tuple]] = field(default_factory=dict, repr=False)
    # bare names referenced in a route-registration call, per file -- resolved
    # against by_bare_name once the whole project is parsed
    _raw_registrations: dict[str, set[str]] = field(default_factory=dict, repr=False)
    _reachable_files_cache: set[str] | None = field(default=None, repr=False)

    def reachable_files(self) -> set[str]:
        """Files whose top-level code runs: contains an entrypoint, or is
        imported (transitively) from a file that does."""
        if self._reachable_files_cache is not None:
            return self._reachable_files_cache
        root_files = {fn.file for fn in self.funcs.values() if fn.is_entrypoint}
        reachable: set[str] = set()
        frontier = list(root_files)
        while frontier:
            f = frontier.pop()
            if f in reachable:
                continue
            reachable.add(f)
            frontier.extend(self.file_imports.get(f, ()))
        self._reachable_files_cache = reachable
        return reachable


def _decorator_name(dec: ast.expr) -> str | None:
    node = dec
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _base_class_name(base: ast.expr) -> str | None:
    if isinstance(base, ast.Name):
        return base.id
    if isinstance(base, ast.Attribute):
        return base.attr
    return None


def _is_view_base(name: str) -> bool:
    # covers View, APIView, ListView, MethodView, ViewSet, ModelViewSet, ...
    return name.endswith("View") or name.endswith("ViewSet")


class _FileVisitor(ast.NodeVisitor):
    def __init__(self, file: str, graph: ProjectGraph):
        self.file = file
        self.is_test_file = _is_test_file(file)
        self.graph = graph
        self.import_alias_to_module: dict[str, str] = {}  # local name -> module
        self._class_stack: list[str] = []
        self._view_class_stack: list[bool] = []  # parallels _class_stack
        # class+function nesting, for qualname disambiguation only (so two
        # same-named closures in different enclosing functions don't collide)
        self._scope_stack: list[str] = []

        # module scope sits at the bottom of the stack so top-level code
        # attributes there instead of being dropped
        module_node = FuncNode(
            qualname=f"{file}:__module__", file=file, lineno=1, is_module_scope=True,
        )
        graph.funcs[module_node.qualname] = module_node
        self._func_stack: list[FuncNode] = [module_node]

    def visit_ClassDef(self, node: ast.ClassDef):
        is_view = any(
            (base_name := _base_class_name(b)) and _is_view_base(base_name)
            for b in node.bases
        )
        self._class_stack.append(node.name)
        self._view_class_stack.append(is_view)
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()
        self._view_class_stack.pop()
        self._class_stack.pop()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            top = alias.name.split(".")[0]
            local = alias.asname or alias.name.split(".")[0]
            self.import_alias_to_module[local] = top
            self.graph._raw_imports.setdefault(self.file, []).append(("import", alias.name))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            top = node.module.split(".")[0]
            for alias in node.names:
                local = alias.asname or alias.name
                self.import_alias_to_module[local] = top
        self.graph._raw_imports.setdefault(self.file, []).append(("from", node.level, node.module))
        self.generic_visit(node)

    def _handle_func(self, node):
        # full class+function nesting so e.g. ClassA.get vs ClassB.get don't collide
        scope = ".".join(self._scope_stack + [node.name])
        qualname = f"{self.file}:{scope}"
        if qualname in self.graph.funcs:
            qualname = f"{qualname}@{node.lineno}"  # residual collision, e.g. if/else branches
        fn = FuncNode(qualname=qualname, file=self.file, lineno=node.lineno)

        if not self.is_test_file:
            for dec in getattr(node, "decorator_list", []):
                dname = _decorator_name(dec)
                if dname in ENTRYPOINT_DECORATORS:
                    fn.is_entrypoint = True
                    fn.entrypoint_reason = f"@{dname} decorator"

            if node.name == "main":
                fn.is_entrypoint = True
                fn.entrypoint_reason = "function named 'main'"

            if (
                not fn.is_entrypoint
                and self._view_class_stack and self._view_class_stack[-1]
                and node.name in CLASS_BASED_VIEW_METHODS
            ):
                fn.is_entrypoint = True
                fn.entrypoint_reason = f"HTTP method on class-based view ({self._class_stack[-1]})"

        self.graph.funcs[qualname] = fn
        self.graph.by_bare_name.setdefault(node.name, set()).add(qualname)

        self._func_stack.append(fn)
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()
        self._func_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._handle_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._handle_func(node)

    def visit_Name(self, node: ast.Name):
        if self._func_stack and node.id in self.import_alias_to_module:
            self._func_stack[-1].uses_modules.add(self.import_alias_to_module[node.id])
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if self._func_stack:
            fname = None
            if isinstance(node.func, ast.Name):
                fname = node.func.id
                if fname == "ArgumentParser" and not self.is_test_file:
                    self._func_stack[-1].is_entrypoint = True
                    self._func_stack[-1].entrypoint_reason = "uses argparse.ArgumentParser"
            elif isinstance(node.func, ast.Attribute):
                fname = node.func.attr
                if fname == "ArgumentParser" and not self.is_test_file:
                    self._func_stack[-1].is_entrypoint = True
                    self._func_stack[-1].entrypoint_reason = "uses argparse.ArgumentParser"
            if fname:
                self._func_stack[-1].calls.add(fname)

            reg_name = fname if (fname in REGISTRATION_CALL_NAMES and not self.is_test_file) else None
            if reg_name:
                for arg in list(node.args) + [kw.value for kw in node.keywords]:
                    ref = None
                    if isinstance(arg, ast.Name):
                        ref = arg.id
                    elif isinstance(arg, ast.Attribute):
                        ref = arg.attr  # e.g. `views.my_view`
                    if ref:
                        self.graph._raw_registrations.setdefault(self.file, set()).add(ref)
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        is_main_guard = (
            isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "__name__"
        )
        if is_main_guard:
            synth = FuncNode(qualname=f"{self.file}:__main_block__", file=self.file, lineno=node.lineno,
                              is_entrypoint=True, entrypoint_reason="if __name__ == '__main__' block")
            self.graph.funcs[synth.qualname] = synth
            self._func_stack.append(synth)
            for stmt in node.body:
                self.visit(stmt)
            self._func_stack.pop()
        else:
            self.generic_visit(node)


def _resolve_absolute_import(project_root: Path, dotted: str) -> str | None:
    """`import a.b.c` -> project-relative file, if it exists in this project."""
    parts = dotted.split(".")
    for candidate in (
        project_root.joinpath(*parts).with_suffix(".py"),
        project_root.joinpath(*parts, "__init__.py"),
    ):
        if candidate.exists():
            return str(candidate.relative_to(project_root))
    return None


def _resolve_relative_import(project_root: Path, current_file_rel: str, level: int, module: str | None) -> str | None:
    """`from . import x` / `from .mod import y` / `from ..pkg.mod import y`."""
    target_dir = (project_root / current_file_rel).parent
    for _ in range(level - 1):
        target_dir = target_dir.parent
    if module:
        parts = module.split(".")
        for candidate in (
            target_dir.joinpath(*parts).with_suffix(".py"),
            target_dir.joinpath(*parts, "__init__.py"),
        ):
            if candidate.exists():
                return str(candidate.relative_to(project_root))
        return None
    candidate = target_dir / "__init__.py"
    return str(candidate.relative_to(project_root)) if candidate.exists() else None


def _resolve_registrations(graph: ProjectGraph) -> None:
    """Mark functions referenced in a URL/route registration call as
    entrypoints, since the framework calls them, not our call graph."""
    for file, names in graph._raw_registrations.items():
        for name in names:
            candidates = graph.by_bare_name.get(name, ())
            same_file = [qn for qn in candidates if graph.funcs[qn].file == file]
            targets = same_file or candidates
            for qn in targets:
                fn = graph.funcs[qn]
                if not fn.is_entrypoint:
                    fn.is_entrypoint = True
                    fn.entrypoint_reason = "referenced in a URL/route registration call"


def _resolve_file_imports(project_root: Path, graph: ProjectGraph) -> None:
    for file, entries in graph._raw_imports.items():
        resolved: set[str] = set()
        for entry in entries:
            try:
                if entry[0] == "import":
                    target = _resolve_absolute_import(project_root, entry[1])
                else:  # "from"
                    _, level, module = entry
                    target = (
                        _resolve_relative_import(project_root, file, level, module)
                        if level
                        else (_resolve_absolute_import(project_root, module) if module else None)
                    )
            except (ValueError, OSError):
                target = None
            if target and target != file:
                resolved.add(target)
        if resolved:
            graph.file_imports[file] = resolved


def build_project_graph(project_root: Path, exclude_dirs: set[str] | None = None) -> ProjectGraph:
    exclude_dirs = exclude_dirs or {".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist"}
    graph = ProjectGraph()
    for py_file in project_root.rglob("*.py"):
        if any(part in exclude_dirs for part in py_file.parts):
            continue
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue
        rel = str(py_file.relative_to(project_root))
        _FileVisitor(rel, graph).visit(tree)
    _resolve_registrations(graph)
    _resolve_file_imports(project_root, graph)
    return graph


def find_reachable_users(graph: ProjectGraph, module_name: str) -> list[FuncNode]:
    """Functions that use `module_name` AND are reachable from some entrypoint."""
    direct_users = [fn for fn in graph.funcs.values() if module_name in fn.uses_modules]
    if not direct_users:
        return []

    # BFS from every entrypoint through the call graph; a user is "reachable" if visited.
    entrypoints = [fn for fn in graph.funcs.values() if fn.is_entrypoint]
    reachable: set[str] = set()
    frontier = list(entrypoints)
    visited_qn = set()
    while frontier:
        fn = frontier.pop()
        if fn.qualname in visited_qn:
            continue
        visited_qn.add(fn.qualname)
        reachable.add(fn.qualname)
        for called_name in fn.calls:
            candidates = graph.by_bare_name.get(called_name, ())
            # prefer a same-file match; fall back to every same-named function
            # project-wide otherwise (over-approximates, but missing a real
            # call is worse than a false one -- see the KNOWN_LIMITATION tests)
            same_file = [qn for qn in candidates if graph.funcs[qn].file == fn.file]
            targets = same_file or candidates
            for callee_qn in targets:
                if callee_qn not in visited_qn:
                    frontier.append(graph.funcs[callee_qn])

    # module-level usage runs on import, not on a call -- credit it via the
    # file-level import graph instead
    reachable_files = graph.reachable_files()

    return [
        fn for fn in direct_users
        if fn.qualname in reachable
        or (fn.is_module_scope and fn.file in reachable_files)
    ]


def all_users(graph: ProjectGraph, module_name: str) -> list[FuncNode]:
    return [fn for fn in graph.funcs.values() if module_name in fn.uses_modules]
