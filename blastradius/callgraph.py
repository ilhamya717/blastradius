"""Best-effort static analysis: which project functions use which dependencies,
and whether those functions are reachable from an entrypoint.

This is intentionally heuristic (no type inference, no cross-file alias
resolution beyond imports) -- the goal is a useful signal, not soundness.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

ENTRYPOINT_DECORATORS = {
    "route", "get", "post", "put", "delete", "patch",  # Flask/FastAPI/Starlette
    "websocket", "task", "command", "cli",              # Celery/Click
}


@dataclass
class FuncNode:
    qualname: str          # "path/to/file.py:funcname" (or "path/to/file.py:__module__")
    file: str
    lineno: int
    calls: set[str] = field(default_factory=set)        # other qualnames or bare names called
    uses_modules: set[str] = field(default_factory=set)  # top-level module names referenced
    is_entrypoint: bool = False
    entrypoint_reason: str | None = None
    is_module_scope: bool = False  # True for the synthetic "top of file" node


@dataclass
class ProjectGraph:
    funcs: dict[str, FuncNode] = field(default_factory=dict)
    # bare function name -> set of qualnames (for approximate call resolution)
    by_bare_name: dict[str, set[str]] = field(default_factory=dict)
    # file -> set of other project files it locally imports (resolved from
    # import statements), used to propagate reachability into module-level
    # (top-of-file) code that executes on import, not on being called.
    file_imports: dict[str, set[str]] = field(default_factory=dict)
    _raw_imports: dict[str, list[tuple]] = field(default_factory=dict, repr=False)
    _reachable_files_cache: set[str] | None = field(default=None, repr=False)

    def reachable_files(self) -> set[str]:
        """Files whose top-level code is known to execute: any file containing
        a detected entrypoint, plus anything transitively imported from one."""
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


class _FileVisitor(ast.NodeVisitor):
    def __init__(self, file: str, graph: ProjectGraph):
        self.file = file
        self.graph = graph
        # alias -> top-level module name, e.g. "np" -> "numpy", "requests" -> "requests"
        self.import_alias_to_module: dict[str, str] = {}
        self._class_stack: list[str] = []

        # module-level ("top of file") scope always sits at the bottom of the
        # stack, so any usage/call outside a function body attributes there
        # instead of being silently dropped.
        module_node = FuncNode(
            qualname=f"{file}:__module__", file=file, lineno=1, is_module_scope=True,
        )
        graph.funcs[module_node.qualname] = module_node
        self._func_stack: list[FuncNode] = [module_node]

    def visit_ClassDef(self, node: ast.ClassDef):
        self._class_stack.append(node.name)
        self.generic_visit(node)
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
        # include enclosing class name so e.g. ClassA.get and ClassB.get in the
        # same file don't collide into one node during call resolution
        scope = ".".join(self._class_stack + [node.name])
        qualname = f"{self.file}:{scope}"
        fn = FuncNode(qualname=qualname, file=self.file, lineno=node.lineno)

        for dec in getattr(node, "decorator_list", []):
            dname = _decorator_name(dec)
            if dname in ENTRYPOINT_DECORATORS:
                fn.is_entrypoint = True
                fn.entrypoint_reason = f"@{dname} decorator"

        if node.name == "main":
            fn.is_entrypoint = True
            fn.entrypoint_reason = "function named 'main'"

        self.graph.funcs[qualname] = fn
        self.graph.by_bare_name.setdefault(node.name, set()).add(qualname)

        self._func_stack.append(fn)
        self.generic_visit(node)
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
        # catches module.attr usage even when module itself isn't a bare Name load elsewhere
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if self._func_stack:
            fname = None
            if isinstance(node.func, ast.Name):
                fname = node.func.id
                if fname == "ArgumentParser":
                    self._func_stack[-1].is_entrypoint = True
                    self._func_stack[-1].entrypoint_reason = "uses argparse.ArgumentParser"
            elif isinstance(node.func, ast.Attribute):
                fname = node.func.attr
                if fname == "ArgumentParser":
                    self._func_stack[-1].is_entrypoint = True
                    self._func_stack[-1].entrypoint_reason = "uses argparse.ArgumentParser"
            if fname:
                self._func_stack[-1].calls.add(fname)
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        # heuristic: `if __name__ == "__main__":` body calls are entrypoint-adjacent
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
    """`import a.b.c` / `from a.b.c import x` -> project-relative file, if it's
    actually part of this project (external packages simply won't exist here)."""
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
    _resolve_file_imports(project_root, graph)
    return graph


def find_reachable_users(graph: ProjectGraph, module_name: str) -> list[FuncNode]:
    """Functions that use `module_name` AND are reachable from some entrypoint."""
    direct_users = [fn for fn in graph.funcs.values() if module_name in fn.uses_modules]
    if not direct_users:
        return []

    # BFS backward-ish: from each entrypoint, walk the (approximate) call graph
    # forward and mark visited; a user is "reachable" if visited.
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
            # prefer same-file candidates: a bare call almost always resolves
            # to something in scope (same file/class) rather than a same-named
            # function in an unrelated file. Only fall back to every
            # same-named function project-wide when nothing local matches --
            # that fallback is deliberately permissive (over-approximates
            # reachability) since missing a real call is worse than a false one.
            same_file = [qn for qn in candidates if graph.funcs[qn].file == fn.file]
            targets = same_file or candidates
            for callee_qn in targets:
                if callee_qn not in visited_qn:
                    frontier.append(graph.funcs[callee_qn])

    # module-level ("top of file") usage isn't reached by a call at all -- it
    # runs as a side effect of the file being imported. Credit it separately
    # via the file-level import graph rooted at files that hold an entrypoint.
    reachable_files = graph.reachable_files()

    return [
        fn for fn in direct_users
        if fn.qualname in reachable
        or (fn.is_module_scope and fn.file in reachable_files)
    ]


def all_users(graph: ProjectGraph, module_name: str) -> list[FuncNode]:
    return [fn for fn in graph.funcs.values() if module_name in fn.uses_modules]
