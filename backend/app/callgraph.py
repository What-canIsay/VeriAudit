"""Multi-language call graph + cross-procedure reachability, with a precision ladder.

Reachability precision, tried high→low (each degrades to the next on unavailability/error):

    CodeQL  >  Joern  >  Tree-sitter call graph  >  file-level heuristic

- CodeQL / Joern are the high-precision rungs (semantic dataflow / CPG). They are used
  only when their binaries are present; any failure degrades safely to the next rung.
- The Tree-sitter rung builds a real cross-file, name-resolved call graph and is the
  default working engine (no external binary, multi-language incl. PHP). To stay honest
  under imprecise name resolution it only ASSERTS a *confirmed* reachable path (a pure
  gain + call-path evidence for the Validator); it never hard-rejects a candidate on a
  missed edge (that would be a false negative). Only the precise rungs may reject.
- The floor is the original file-level heuristic in analysis.reachability_check.

Built once per project (cached), consumed by the Tracer's reachability gate and exposed
to the agents via the `call_path` / `who_calls` tools.
"""
from __future__ import annotations

import glob
import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import analysis
from .config import DATA_DIR, settings

try:
    from tree_sitter_language_pack import get_parser
    _HAS_TS = True
except Exception:  # pragma: no cover
    _HAS_TS = False

# tree-sitter node types per language (defensive: unknown grammars just fall through)
_FUNC_TYPES = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "method_definition", "generator_function_declaration",
                   "function_expression", "arrow_function"},
    "typescript": {"function_declaration", "method_definition", "generator_function_declaration",
                   "function_expression", "arrow_function"},
    "php": {"function_definition", "method_declaration"},
    "go": {"function_declaration", "method_declaration"},
    "java": {"method_declaration", "constructor_declaration"},
}
_CALL_TYPES = {
    "python": {"call"},
    "javascript": {"call_expression", "new_expression"},
    "typescript": {"call_expression", "new_expression"},
    "php": {"function_call_expression", "member_call_expression", "scoped_call_expression",
            "object_creation_expression"},
    "go": {"call_expression"},
    "java": {"method_invocation", "object_creation_expression"},
}
_TS_LANG = {"python": "python", "javascript": "javascript", "typescript": "typescript",
            "php": "php", "go": "go", "java": "java"}

# module-level cache: str(root) -> Graph | None (None = build failed, use heuristic)
_CACHE: Dict[str, "Graph"] = {}


class Graph:
    def __init__(self) -> None:
        self.engine = "treesitter"
        self.lang = ""
        # func key = (file, start_line, name)
        self.funcs: Dict[tuple, dict] = {}
        self.defs_by_name: Dict[str, List[tuple]] = {}
        self.edges: Dict[tuple, set] = {}          # caller_key -> {callee_key}
        self.redges: Dict[tuple, set] = {}         # callee_key -> {caller_key}
        self.roots: set = set()                    # funcs with no in-repo callers (external surface)
        self.spans_by_file: Dict[str, List[tuple]] = {}   # file -> [(start,end,key)]

    def _finalize(self) -> None:
        self.redges = {}
        for caller, callees in self.edges.items():
            for c in callees:
                self.redges.setdefault(c, set()).add(caller)
        self.roots = {k for k in self.funcs if not self.redges.get(k)}

    def set_edges_from(self, edge_tuples, engine: str) -> None:
        """Replace edges with higher-precision ones (CodeQL/Joern), mapping each endpoint
        (file, line, name) onto our Tree-sitter function keys (spans stay from TS). Keys
        align because both use the definition line; a small tolerance covers decorators."""
        idx: Dict[tuple, list] = {}
        for key, f in self.funcs.items():
            idx.setdefault((f["file"], f["name"]), []).append((f["start"], key))

        def resolve(file: str, line: int, name: str):
            cands = idx.get((file, name))
            if not cands:
                return None
            return min(cands, key=lambda sk: abs(sk[0] - line))[1]

        new_edges: Dict[tuple, set] = {}
        for cf, cl, cn, ef, el, en in edge_tuples:
            a, b = resolve(cf, int(cl), cn), resolve(ef, int(el), en)
            if a and b and a != b:
                new_edges.setdefault(a, set()).add(b)
        self.edges = new_edges
        self.engine = engine
        self._finalize()

    def enclosing(self, file: str, line: int) -> Optional[tuple]:
        best = None
        best_span = None
        for start, end, key in self.spans_by_file.get(file, []):
            if start <= line <= end and (best_span is None or (end - start) < best_span):
                best, best_span = key, end - start
        return best

    def _fwd(self, starts: dict, sink_key: tuple) -> Optional[List[tuple]]:
        seen = set(starts)
        frontier = [(k, [k]) for k in starts]
        while frontier:
            cur, path = frontier.pop()
            for nxt in self.edges.get(cur, ()):  # type: ignore
                if nxt == sink_key:
                    return path + [nxt]
                if nxt not in seen:
                    seen.add(nxt)
                    frontier.append((nxt, path + [nxt]))
        return None

    def _back_to_root(self, sink_key: tuple) -> Optional[List[tuple]]:
        """Walk callers backward from sink to any external root; return root→…→sink."""
        seen = {sink_key}
        frontier = [(sink_key, [sink_key])]
        while frontier:
            cur, path = frontier.pop()
            if cur in self.roots and len(path) > 1:
                return list(reversed(path))
            for prev in self.redges.get(cur, ()):  # type: ignore
                if prev not in seen:
                    seen.add(prev)
                    frontier.append((prev, path + [prev]))
        return None

    def reachable(self, sink_file: str, sink_line: int, entry_locs: List[dict]) -> Optional[dict]:
        """Return a CONFIRMED reachable result (with call path) or None (defer).
        Positive-only: asserts reachability with a path when one is found; never rejects."""
        sink_key = self.enclosing(sink_file, sink_line)
        if sink_key is None:
            return None    # top-level/script sink → let the floor decide (it executes anyway)
        # 1) from pattern-detected entrypoints (the most trustworthy entry)
        entry_keys = {}
        for e in entry_locs:
            loc = e.get("location", e)
            k = self.enclosing(loc.get("file", ""), loc.get("line", 0))
            if k is not None:
                entry_keys[k] = loc
        if sink_key in entry_keys:
            return self._hit([sink_key], entry_keys[sink_key])
        if entry_keys:
            path = self._fwd(entry_keys, sink_key)
            if path:
                return self._hit(path, entry_keys[path[0]])
        # 2) the sink function itself is an external root (directly invoked from outside)
        if sink_key in self.roots:
            return self._hit([sink_key], self._loc(sink_key))
        # 3) backward: recover a chain from an external root to the sink
        back = self._back_to_root(sink_key)
        if back:
            return self._hit(back, self._loc(back[0]))
        return None   # no path found → DEFER (don't reject: name resolution may miss edges)

    def _loc(self, key: tuple) -> dict:
        f = self.funcs.get(key, {})
        return {"file": key[0], "line": key[1], "function": f.get("name")}

    def _hit(self, path_keys: List[tuple], entry_loc: dict) -> dict:
        names = [self.funcs[k]["name"] for k in path_keys if k in self.funcs]
        return {"reachable": True, "confidence": 0.88, "preconditions": [],
                "entry_points": [entry_loc],
                "path": [{"function": self.funcs[k]["name"], "file": k[0], "line": k[1]}
                         for k in path_keys if k in self.funcs],
                "note": f"调用图确认可达：{' → '.join(names)}", "engine": self.engine}

    def callers_of(self, name: str) -> List[dict]:
        out = []
        for caller, callees in self.edges.items():
            for c in callees:
                if c in self.funcs and self.funcs[c]["name"] == name:
                    out.append({"function": self.funcs[caller]["name"],
                                "file": caller[0], "line": caller[1]})
        return out


# --------------------------------------------------------------------------- #
# Tree-sitter call graph builder
# --------------------------------------------------------------------------- #
def _node_name(node) -> Optional[str]:
    n = node.child_by_field_name("name")
    if n is not None:
        return n.text.decode("utf-8", "replace")
    for ch in node.children:                       # fallback: first identifier-ish child
        if "identifier" in ch.type or ch.type == "name":
            return ch.text.decode("utf-8", "replace")
    return None


def _callee_name(node) -> Optional[str]:
    target = (node.child_by_field_name("function") or node.child_by_field_name("name")
              or node.child_by_field_name("constructor"))
    if target is None:
        target = node.children[0] if node.children else None
    if target is None:
        return None
    # rightmost identifier = the called method/function short name
    last = None
    stack = [target]
    while stack:
        cur = stack.pop()
        if cur.type in ("identifier", "name") or "identifier" in cur.type:
            last = cur.text.decode("utf-8", "replace")
        stack.extend(cur.children)
    return last


def _extract(root_node, lang: str) -> Tuple[List[dict], List[dict]]:
    func_types = _FUNC_TYPES.get(lang, set())
    call_types = _CALL_TYPES.get(lang, set())
    defs: List[dict] = []
    calls: List[dict] = []

    def walk(node, enclosing):
        cur_enc = enclosing
        if node.type in func_types:
            name = _node_name(node)
            if name:
                d = {"name": name, "start": node.start_point[0] + 1, "end": node.end_point[0] + 1}
                defs.append(d)
                cur_enc = d
        if node.type in call_types:
            cn = _callee_name(node)
            if cn:
                calls.append({"callee": cn, "line": node.start_point[0] + 1, "enc": cur_enc})
        for ch in node.children:
            walk(ch, cur_enc)

    walk(root_node, None)
    return defs, calls


def _build_ts(root: Path) -> Optional[Graph]:
    if not _HAS_TS:
        return None
    g = Graph()
    file_calls: List[Tuple[str, dict]] = []
    try:
        for p, lang in analysis.iter_source_files(root):
            ts_lang = _TS_LANG.get(lang)
            if not ts_lang or ts_lang not in _FUNC_TYPES:
                continue
            try:
                parser = get_parser(ts_lang)
                code = p.read_bytes()
                tree = parser.parse(code)
            except Exception:
                continue
            rel = analysis._rel(root, p)
            defs, calls = _extract(tree.root_node, ts_lang)
            spans = []
            for d in defs:
                key = (rel, d["start"], d["name"])
                g.funcs[key] = {"name": d["name"], "file": rel, "start": d["start"], "end": d["end"]}
                g.defs_by_name.setdefault(d["name"], []).append(key)
                spans.append((d["start"], d["end"], key))
            g.spans_by_file[rel] = spans
            for c in calls:
                if c["enc"] is not None:
                    caller_key = (rel, c["enc"]["start"], c["enc"]["name"])
                    file_calls.append((caller_key, c))
        # resolve edges by name (name-based; imprecise but general)
        for caller_key, c in file_calls:
            for callee_key in g.defs_by_name.get(c["callee"], ()):  # type: ignore
                if callee_key != caller_key:
                    g.edges.setdefault(caller_key, set()).add(callee_key)
        g._finalize()
    except Exception:
        return None
    return g if g.funcs else None


def get_graph(root: Path) -> Optional[Graph]:
    """Build ONE best-available call graph per project (cached), via the precision ladder:
    Tree-sitter provides function spans; CodeQL (>Joern) refine the EDGES when available.
    Both the reachability gate and the call_path/who_calls tools share this graph."""
    key = str(root)
    if key not in _CACHE:
        g = _build_ts(root)               # spans + baseline edges (always, multi-language)
        if g is not None:
            lang = _primary_lang(root)
            g.lang = lang
            try:
                edges = _codeql_edges(root, lang) or _joern_edges(root, lang)   # CodeQL > Joern
            except Exception:
                edges = None
            if edges is not None:
                g.set_edges_from(edges[0], edges[1])   # (tuples, engine)
        _CACHE[key] = g
    return _CACHE.get(key)


def clear_cache(root: Optional[Path] = None) -> None:
    if root is None:
        _CACHE.clear()
    else:
        _CACHE.pop(str(root), None)


def _primary_lang(root: Path) -> str:
    try:
        langs = analysis.detect_stack(root).get("languages", {})
        return next(iter(langs), "")
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# High-precision EDGE providers (CodeQL / Joern). Return (edge_tuples, engine) or None.
# Wrapped by callers so ANY failure degrades to the Tree-sitter edges.
# --------------------------------------------------------------------------- #
# Languages we auto-run CodeQL edge-refinement on. VERIFIED: python only (query bundled +
# tested). javascript/ruby: no-build & CodeQL-supported, but the calls.ql is NOT written
# yet → they degrade to Tree-sitter (add cg_queries/<lang>/calls.ql to enable). go/java/
# csharp need a successful build (fragile) → not auto-run. CodeQL has NO PHP → Tree-sitter.
_CODEQL_LANG = {"python": "python"}


def _codeql_packs(codeql: str) -> Optional[str]:
    p = Path(codeql).resolve().parent / "qlpacks"
    return str(p) if p.exists() else None


def _codeql_db(root: Path, cql_lang: str, codeql: str) -> Optional[Path]:
    import hashlib
    cache = DATA_DIR / "codeql" / (hashlib.md5(str(root).encode()).hexdigest()[:12] + "-" + cql_lang)
    if (cache / "codeql-database.yml").exists():
        return cache
    cache.parent.mkdir(parents=True, exist_ok=True)
    try:
        r = subprocess.run([codeql, "database", "create", str(cache), f"--language={cql_lang}",
                            f"--source-root={root}", "--overwrite", f"--ram={settings.codeql_ram_mb}"],
                           capture_output=True, timeout=settings.codeql_timeout_sec)
        return cache if (r.returncode == 0 and (cache / "codeql-database.yml").exists()) else None
    except Exception:
        return None


def _codeql_edges(root: Path, lang: str):
    if not getattr(settings, "enable_codeql_callgraph", True):
        return None
    cql_lang = _CODEQL_LANG.get(lang)
    if not cql_lang:
        return None
    codeql = shutil.which("codeql")
    ql = Path(__file__).parent / "cg_queries" / cql_lang / "calls.ql"
    if not codeql or not ql.exists():
        return None
    db = _codeql_db(root, cql_lang, codeql)
    if not db:
        return None
    packs = _codeql_packs(codeql)
    out = db / "calls.bqrs"
    try:
        cmd = [codeql, "query", "run", "--database", str(db), "--output", str(out),
               f"--ram={settings.codeql_ram_mb}"]
        if packs:
            cmd += ["--additional-packs", packs]
        cmd.append(str(ql))
        r = subprocess.run(cmd, capture_output=True, timeout=settings.codeql_timeout_sec)
        if r.returncode != 0:
            return None
        dec = subprocess.run([codeql, "bqrs", "decode", "--format=csv", str(out)],
                             capture_output=True, text=True, timeout=120)
        if dec.returncode != 0:
            return None
        # query SUCCEEDED → trust CodeQL edges even if empty (flat apps have no internal
        # function→function edges); returning None here would mislabel as tree-sitter.
        return (_parse_csv(dec.stdout), "codeql")
    except Exception:
        return None


def _joern_paths():
    """Locate joern-cli + a JDK 17+ (settings override, else auto-detect under D:/Tools)."""
    cands = ([settings.joern_dir] if settings.joern_dir else []) + ["D:/Tools/joern-cli"]
    joern = next((Path(c) for c in cands if (Path(c) / "joern.bat").exists()
                  or (Path(c) / "joern").exists()), None)
    if joern is None:
        w = shutil.which("joern")
        joern = Path(w).parent if w else None
    java = None
    jh = settings.joern_java_home
    if jh and ((Path(jh) / "bin" / "java.exe").exists() or (Path(jh) / "bin" / "java").exists()):
        java = Path(jh)
    else:
        for g in sorted(glob.glob("D:/Tools/jdk-1[789]*") + glob.glob("D:/Tools/jdk-2*"), reverse=True):
            if (Path(g) / "bin" / "java.exe").exists() or (Path(g) / "bin" / "java").exists():
                java = Path(g)
                break
    return joern, java


def _joern_env(java: Path):
    env = os.environ.copy()
    env["JAVA_HOME"] = str(java)
    # some Joern frontends shell out to an interpreter (php2cpg→php); node/go are already
    # on the inherited PATH. Prepend the JDK + any tool dirs we manage under D:/Tools.
    extra = [str(java / "bin")]
    for tool in ("D:/Tools/php",):
        if Path(tool).exists():
            extra.append(tool)
    env["PATH"] = os.pathsep.join(extra) + os.pathsep + env.get("PATH", "")
    return env


def _joern_launch(joern: Path, name: str):
    bat = joern / (name + ".bat")
    return ["cmd", "/c", str(bat)] if bat.exists() else [str(joern / name)]


def _joern_edges(root: Path, lang: str):
    """Multi-language (incl. PHP/Go/Java, no build) call edges via Joern CPG. Below CodeQL
    in the ladder; degrades to Tree-sitter on any failure."""
    if not settings.enable_joern_callgraph:
        return None
    joern, java = _joern_paths()
    if not (joern and java):
        return None
    try:
        cache = DATA_DIR / "joern" / (hashlib.md5(str(root).encode()).hexdigest()[:12])
        cache.parent.mkdir(parents=True, exist_ok=True)
        cpg = cache.with_suffix(".cpg.bin")
        env = _joern_env(java)
        if not cpg.exists():
            r = subprocess.run(_joern_launch(joern, "joern-parse") + [str(root), "-o", str(cpg)],
                               env=env, capture_output=True, timeout=settings.joern_timeout_sec)
            if not cpg.exists():
                return None
        script = cache.with_suffix(".sc")
        cpg_fwd = str(cpg).replace("\\", "/")
        script.write_text(
            f'importCpg("{cpg_fwd}")\n'
            'cpg.call.foreach { c =>\n'
            '  val caller = c.method\n'
            '  c.callee.filterNot(_.isExternal).foreach { callee =>\n'
            '    println("EDGE\\t" + caller.filename + "\\t" + caller.lineNumber.getOrElse(-1) +'
            ' "\\t" + caller.name + "\\t" + callee.filename + "\\t" +'
            ' callee.lineNumber.getOrElse(-1) + "\\t" + callee.name)\n'
            '  }\n'
            '}\n', encoding="utf-8")
        r = subprocess.run(_joern_launch(joern, "joern") + ["--script", str(script)],
                           env=env, capture_output=True, timeout=settings.joern_timeout_sec)
        rows = []
        for line in (r.stdout or b"").decode("utf-8", "replace").splitlines():
            if line.startswith("EDGE\t"):
                p = line.split("\t")
                if len(p) >= 7 and not p[3].startswith("<") and not p[6].startswith("<"):
                    rows.append((p[1].replace("\\", "/"), p[2], p[3],
                                 p[4].replace("\\", "/"), p[5], p[6]))
        return (rows, "joern") if rows else None
    except Exception:
        return None


def _parse_csv(text: str):
    import csv
    import io
    out = []
    rd = csv.reader(io.StringIO(text or ""))
    rows = list(rd)
    for row in rows[1:]:   # skip header
        if len(row) >= 6:
            out.append((row[0], row[1], row[2], row[3], row[4], row[5]))
    return out


# --------------------------------------------------------------------------- #
# Public: laddered reachability (richer replacement for the file-level check)
# --------------------------------------------------------------------------- #
def reachability(root: Path, candidate: dict, entrypoints: List[dict]) -> dict:
    loc = candidate.get("location", {})
    sink_file, sink_line = loc.get("file", ""), loc.get("line", 0)
    g = get_graph(root)
    if g is not None:
        try:
            r = g.reachable(sink_file, sink_line, entrypoints)
        except Exception:
            r = None
        if r is not None:
            return r
    return analysis.reachability_check(root, candidate, entrypoints)   # file-level floor


def call_path(root: Path, from_file: str, from_line: int, to_file: str, to_line: int) -> dict:
    """Concrete function-level path between two code locations (for precise PoC)."""
    g = get_graph(root)
    if g is None:
        return {"available": False, "note": "调用图不可用（回落启发式）"}
    src = g.enclosing(from_file, from_line)
    dst = g.enclosing(to_file, to_line)
    if not src or not dst:
        return {"available": True, "path": None, "note": "端点不在任何函数内（可能为顶层代码）"}
    if src == dst:
        return {"available": True, "path": [g.funcs[src]["name"]]}
    seen = {src}
    frontier = [(src, [src])]
    while frontier:
        cur, path = frontier.pop()
        for nxt in g.edges.get(cur, ()):  # type: ignore
            if nxt == dst:
                return {"available": True,
                        "path": [{"function": g.funcs[k]["name"], "file": k[0], "line": k[1]}
                                 for k in path + [nxt] if k in g.funcs]}
            if nxt not in seen:
                seen.add(nxt)
                frontier.append((nxt, path + [nxt]))
    return {"available": True, "path": None, "note": "未在调用图中发现路径（可能为动态派发/框架路由）"}


def who_calls(root: Path, symbol: str) -> dict:
    g = get_graph(root)
    if g is None:
        return {"available": False}
    return {"available": True, "callers": g.callers_of(symbol)[:40]}


# --------------------------------------------------------------------------- #
# Degradation reporting: which engine actually ran vs the best achievable, + why.
# --------------------------------------------------------------------------- #
_ENGINE_RANK = {"heuristic": 0, "treesitter": 1, "joern": 2, "codeql": 3}
# per-language Joern frontend that shells out to an external interpreter
_JOERN_FRONTEND_TOOL = {"php": "php", "javascript": "node", "typescript": "node", "go": "go"}


def _ideal_engine(lang: str) -> str:
    if lang == "python":
        return "codeql"          # bundled query + no build
    if lang in ("php", "javascript", "typescript", "go", "java", "ruby", "c", "cpp", "csharp"):
        return "joern"
    return "treesitter"


def _degrade_reason(root: Path, lang: str, engine: str, ideal: str) -> str:
    if ideal == "codeql" and engine != "codeql":
        if not settings.enable_codeql_callgraph:
            return "ENABLE_CODEQL_CALLGRAPH=false（已关闭）"
        if not shutil.which("codeql"):
            return "未检测到 codeql 可执行文件（请安装 CodeQL CLI 并置于 PATH）"
        return f"CodeQL 运行失败/超时/内存不足，已降级到 {engine}（见 CODEQL_RAM_MB / CODEQL_TIMEOUT_SEC）"
    if ideal == "joern" and engine not in ("joern", "codeql"):
        if not settings.enable_joern_callgraph:
            return "ENABLE_JOERN_CALLGRAPH=false（已关闭）"
        joern, java = _joern_paths()
        if not joern:
            return "未找到 joern-cli（设置 JOERN_DIR 或置于 D:/Tools/joern-cli）"
        if not java:
            return "未找到 JDK 17+（设置 JOERN_JAVA_HOME 或置于 D:/Tools/jdk-2x）"
        tool = _JOERN_FRONTEND_TOOL.get(lang)
        if tool and not shutil.which(tool) and not (lang == "php" and Path("D:/Tools/php/php.exe").exists()):
            return f"缺少 {tool}（{lang} 的 Joern 前端需要它；请安装并置于 PATH）"
        return f"Joern 运行失败/超时，已降级到 {engine}（见 JOERN_TIMEOUT_SEC / 内存）"
    return ""


def status(root: Path) -> dict:
    """Report the call-graph engine actually in use vs the best achievable for this
    project's language, plus an actionable degradation reason (for the UI warning)."""
    try:
        g = get_graph(root)
    except Exception:
        g = None
    engine = g.engine if g is not None else "heuristic"
    lang = (g.lang if g is not None and g.lang else _primary_lang(root))
    ideal = _ideal_engine(lang)
    degraded = _ENGINE_RANK.get(engine, 0) < _ENGINE_RANK.get(ideal, 0)
    return {"engine": engine, "lang": lang, "ideal": ideal, "degraded": degraded,
            "reason": _degrade_reason(root, lang, engine, ideal) if degraded else ""}
