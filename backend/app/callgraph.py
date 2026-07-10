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
import sys
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import analysis
from .config import DATA_DIR, settings

# Build locks: the shared call graph / CodeQL DB / Joern CPG must be built ONCE even when
# multiple workers (parallel Tracer) call in concurrently — double-checked locking so the
# already-built fast path never blocks, but a concurrent first-build can't race/corrupt.
_GRAPH_LOCK = threading.Lock()
_DB_LOCK = threading.Lock()
_CPG_LOCK = threading.Lock()

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
        self.callsites: Dict[tuple, set] = {}      # (caller_key, callee_key) -> {call-site lines}
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
        new_cs: Dict[tuple, set] = {}
        for t in edge_tuples:
            cf, cl, cn, ef, el, en = t[:6]
            a, b = resolve(cf, int(cl), cn), resolve(ef, int(el), en)
            if a and b and a != b:
                new_edges.setdefault(a, set()).add(b)
                if len(t) >= 7 and str(t[6]).lstrip("-").isdigit() and int(t[6]) > 0:
                    new_cs.setdefault((a, b), set()).add(int(t[6]))   # call-site line
        self.edges = new_edges
        self.callsites = new_cs
        self.engine = engine
        self._finalize()

    def _callsite(self, a: tuple, b: tuple) -> Optional[int]:
        s = self.callsites.get((a, b))
        return min(s) if s else None

    def _fanin(self, entry_keys, sink_key) -> int:
        """How many distinct entry functions can reach the sink (multi-path signal)."""
        n = 0
        for k in list(entry_keys)[:30]:
            if k == sink_key or self._fwd({k: 1}, sink_key):
                n += 1
        return n

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
                return self._hit(path, entry_keys[path[0]], self._fanin(entry_keys, sink_key))
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

    def _hit(self, path_keys: List[tuple], entry_loc: dict, fanin: int = 1) -> dict:
        hops, parts = [], []
        prev = None
        for k in path_keys:
            if k not in self.funcs:
                continue
            h = {"function": self.funcs[k]["name"], "file": k[0], "line": k[1]}
            cs = self._callsite(prev, k) if prev else None
            if cs:
                h["called_at"] = f"{prev[0]}:{cs}"
                parts.append(f"—(调用点 {prev[0]}:{cs})→")
            elif prev:
                parts.append("→")
            parts.append(f"{h['function']}@{h['file']}:{h['line']}")
            hops.append(h)
            prev = k
        note = "调用图确认可达：" + " ".join(parts)
        if fanin > 1:
            note += f"；另有共 {fanin} 个入口可达此点（此为最短其一，可能还有其它路径）"
        return {"reachable": True, "confidence": 0.88, "preconditions": [],
                "entry_points": [entry_loc], "path": hops, "reachable_from_entries": fanin,
                "note": note, "engine": self.engine}

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
                    g.callsites.setdefault((caller_key, callee_key), set()).add(c["line"])
        g._finalize()
    except Exception:
        return None
    return g if g.funcs else None


def get_graph(root: Path) -> Optional[Graph]:
    """Build ONE best-available call graph per project (cached), via the precision ladder:
    Tree-sitter provides function spans; CodeQL (>Joern) refine the EDGES when available.
    Both the reachability gate and the call_path/who_calls tools share this graph."""
    key = str(root)
    if key in _CACHE:
        return _CACHE.get(key)
    with _GRAPH_LOCK:
        if key in _CACHE:                 # built while we waited for the lock
            return _CACHE.get(key)
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
# Languages we auto-run CodeQL edge-refinement on. VERIFIED: python + javascript/typescript
# (calls.ql + dataflow.ql bundled & tested against known source->sink fixtures). TS reuses the
# CodeQL "javascript" extractor. ruby: CodeQL-supported & no-build, but its dataflow libraries
# are heavy to compile under limited RAM and we have no verified fixture → left to Joern (add
# cg_queries/ruby/*.ql once verified to enable). go/java/csharp need a successful build (fragile)
# → not auto-run, handled by Joern. CodeQL has NO PHP extractor → Tree-sitter / Joern.
_CODEQL_LANG = {"python": "python", "javascript": "javascript", "typescript": "javascript"}


def _codeql_packs(codeql: str) -> Optional[str]:
    p = Path(codeql).resolve().parent / "qlpacks"
    return str(p) if p.exists() else None


_CODEQL_ENV: Optional[dict] = None


def _codeql_env() -> dict:
    """Env for CodeQL subprocesses. CodeQL's Python extractor shells out (via cmd.exe) to the
    `python` interpreter AND the Windows `py` launcher; if those dirs aren't on the inherited
    PATH the extractor silently processes NO files ('no source code seen') → a corrupt DB.
    We prepend the dirs of python + the `py` launcher, resolving them robustly so it works no
    matter how the server was launched (not only when they happen to be on the shell PATH)."""
    global _CODEQL_ENV
    if _CODEQL_ENV is not None:
        return _CODEQL_ENV
    env = dict(os.environ)
    cands = [os.path.dirname(sys.executable), sys.base_prefix]     # venv scripts + base python
    for n in ("py", "python", "python3"):                          # whatever is on PATH already
        w = shutil.which(n)
        if w:
            cands.append(os.path.dirname(w))
    la = os.environ.get("LOCALAPPDATA", "")                        # standard `py` launcher homes
    if la:
        cands.append(os.path.join(la, "Programs", "Python", "Launcher"))
    cands += [r"C:\Windows", os.path.join(os.environ.get("WINDIR", r"C:\Windows"))]
    dirs, seen = [], set()
    for d in cands:
        try:
            d = os.path.normpath(d) if d else ""
        except Exception:
            d = ""
        if d and os.path.isdir(d) and d.lower() not in seen:
            seen.add(d.lower())
            dirs.append(d)
    if dirs:
        env["PATH"] = os.pathsep.join(dirs) + os.pathsep + env.get("PATH", "")
    _CODEQL_ENV = env
    return env


def _db_complete(cache: Path) -> bool:
    """A CodeQL DB is only usable if BOTH the manifest AND the extracted dataset dir exist.
    A create that was killed (timeout/OOM) writes codeql-database.yml EARLY but never finishes
    the db-<lang> dataset — checking only the yml (the old bug) reused that corrupt DB forever,
    so every query failed with 'db-<lang> does not exist' → permanent degrade to Joern."""
    if not (cache / "codeql-database.yml").exists():
        return False
    return any(p.is_dir() for p in cache.glob("db-*"))


def _codeql_db_timeout(root: Path) -> int:
    """DB creation is the heavy one-time step (large projects were killed at the 300s query
    timeout). Scale the cap with project size, bounded. It's only a CAP — create returns as
    soon as it finishes, so a generous ceiling costs nothing on normal builds."""
    base = int(getattr(settings, "codeql_db_timeout_sec", 900))
    try:
        n = sum(1 for _ in analysis.iter_source_files(root))
    except Exception:
        n = 0
    return int(min(2400, max(base, 300 + n)))


def _codeql_db(root: Path, cql_lang: str, codeql: str) -> Optional[Path]:
    cache = DATA_DIR / "codeql" / (hashlib.md5(str(root).encode()).hexdigest()[:12] + "-" + cql_lang)
    if _db_complete(cache):
        return cache
    with _DB_LOCK:   # only ONE builder even under parallel dataflow; others reuse the result
        if _db_complete(cache):
            return cache
        # remove any corrupt/half-built leftover so create starts from a clean slate
        if cache.exists():
            shutil.rmtree(cache, ignore_errors=True)
        cache.parent.mkdir(parents=True, exist_ok=True)
        try:
            r = subprocess.run([codeql, "database", "create", str(cache), f"--language={cql_lang}",
                                f"--source-root={root}", "--overwrite", f"--ram={settings.codeql_ram_mb}"],
                               capture_output=True, timeout=_codeql_db_timeout(root), env=_codeql_env())
            if r.returncode == 0 and _db_complete(cache):
                return cache
        except Exception:
            pass
        # a failed/killed build leaves a corrupt dir → drop it so it is NOT reused next time
        shutil.rmtree(cache, ignore_errors=True)
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
        r = subprocess.run(cmd, capture_output=True, timeout=settings.codeql_timeout_sec, env=_codeql_env())
        if r.returncode != 0:
            return None
        dec = subprocess.run([codeql, "bqrs", "decode", "--format=csv", str(out)],
                             capture_output=True, text=True, timeout=120, env=_codeql_env())
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


def _ensure_joern_cpg(root: Path):
    """Build (once, cached) a Joern CPG. Returns (cpg, joern_dir, java, env) or None.
    Shared by call-edge extraction and the data-flow (taint) query."""
    if not settings.enable_joern_callgraph:
        return None
    joern, java = _joern_paths()
    if not (joern and java):
        return None
    cache = DATA_DIR / "joern" / (hashlib.md5(str(root).encode()).hexdigest()[:12])
    cache.parent.mkdir(parents=True, exist_ok=True)
    cpg = cache.with_suffix(".cpg.bin")
    env = _joern_env(java)
    if not cpg.exists():
        with _CPG_LOCK:   # build the CPG once even under parallel dataflow
            if not cpg.exists():
                try:
                    subprocess.run(_joern_launch(joern, "joern-parse") + [str(root), "-o", str(cpg)],
                                   env=env, capture_output=True, timeout=settings.joern_timeout_sec)
                except Exception:
                    return None
                if not cpg.exists():
                    return None
    return cpg, joern, java, env


def _joern_edges(root: Path, lang: str):
    """Multi-language (incl. PHP/Go/Java, no build) call edges via Joern CPG. Below CodeQL
    in the ladder; degrades to Tree-sitter on any failure."""
    ec = _ensure_joern_cpg(root)
    if not ec:
        return None
    cpg, joern, java, env = ec
    try:
        script = Path(str(cpg) + ".edges.sc")
        cpg_fwd = str(cpg).replace("\\", "/")
        script.write_text(
            f'importCpg("{cpg_fwd}")\n'
            'cpg.call.foreach { c =>\n'
            '  val caller = c.method\n'
            '  c.callee.filterNot(_.isExternal).foreach { callee =>\n'
            '    println("EDGE\\t" + caller.filename + "\\t" + caller.lineNumber.getOrElse(-1) +'
            ' "\\t" + caller.name + "\\t" + callee.filename + "\\t" +'
            ' callee.lineNumber.getOrElse(-1) + "\\t" + callee.name + "\\t" +'
            ' c.lineNumber.getOrElse(-1))\n'
            '  }\n'
            '}\n', encoding="utf-8")
        r = subprocess.run(_joern_launch(joern, "joern") + ["--script", str(script)],
                           env=env, capture_output=True, timeout=settings.joern_timeout_sec)
        rows = []
        for line in (r.stdout or b"").decode("utf-8", "replace").splitlines():
            if line.startswith("EDGE\t"):
                p = line.split("\t")
                if len(p) >= 7 and not p[3].startswith("<") and not p[6].startswith("<"):
                    call_line = p[7] if len(p) >= 8 else "-1"   # call-site line
                    rows.append((p[1].replace("\\", "/"), p[2], p[3],
                                 p[4].replace("\\", "/"), p[5], p[6], call_line))
        return (rows, "joern") if rows else None
    except Exception:
        return None


_DF_CACHE: Dict[tuple, dict] = {}


def dataflow(root: Path, from_file: str, from_line: int, to_file: str, to_line: int) -> dict:
    """Taint/data-flow: does tainted data actually FLOW from (from_file:from_line) to the
    sink at (to_file:to_line)? Precision ladder CodeQL > Joern (mirrors the call graph):
    CodeQL's dataflow is strong for python/js; Joern covers everything else (incl. PHP/Go)
    but is weaker for dynamic languages. Result-memoized. Heavier than the call graph."""
    key = (str(root), from_file, int(from_line), to_file, int(to_line))
    if key in _DF_CACHE:
        return _DF_CACHE[key]
    lang = _primary_lang(root)
    res = None
    if lang in _CODEQL_LANG:
        res = _codeql_dataflow(root, lang, from_file, from_line, to_file, to_line)
    if not (res and res.get("available") and not res.get("error")):
        res = _joern_dataflow(root, from_file, from_line, to_file, to_line)
    _DF_CACHE[key] = res
    return res


def _codeql_dataflow(root: Path, lang: str, from_file: str, from_line: int,
                     to_file: str, to_line: int) -> Optional[dict]:
    """CodeQL taint flow (source/sink via external predicates → query compiles once)."""
    if not getattr(settings, "enable_codeql_callgraph", True):
        return None
    codeql = shutil.which("codeql")
    ql = Path(__file__).parent / "cg_queries" / _CODEQL_LANG[lang] / "dataflow.ql"
    if not codeql or not ql.exists():
        return None
    db = _codeql_db(root, _CODEQL_LANG[lang], codeql)
    if not db:
        return None
    packs = _codeql_packs(codeql)
    # per-call unique temp filenames → parallel dataflow queries never clobber each other's
    # source/sink CSVs or output (fixed names would corrupt concurrent results).
    tok = hashlib.md5(f"{from_file}:{from_line}:{to_file}:{to_line}".encode()).hexdigest()[:10]
    src = db / f"df_src_{tok}.csv"
    snk = db / f"df_snk_{tok}.csv"
    out = db / f"df_{tok}.bqrs"
    try:
        src.write_text(f"{from_file.replace(chr(92), '/')},{int(from_line)}\n", encoding="utf-8")
        snk.write_text(f"{to_file.replace(chr(92), '/')},{int(to_line)}\n", encoding="utf-8")
        cmd = [codeql, "query", "run", "--database", str(db), "--output", str(out),
               f"--ram={settings.codeql_ram_mb}",
               f"--external=srcloc={src}", f"--external=snkloc={snk}"]
        if packs:
            cmd += ["--additional-packs", packs]
        cmd.append(str(ql))
        r = subprocess.run(cmd, capture_output=True, timeout=settings.codeql_timeout_sec, env=_codeql_env())
        if r.returncode != 0:
            return None
        dec = subprocess.run([codeql, "bqrs", "decode", "--format=csv", str(out)],
                             capture_output=True, text=True, timeout=120, env=_codeql_env())
        if dec.returncode != 0:
            return None
        import csv as _csv
        import io as _io
        paths, seen = [], set()
        for row in list(_csv.reader(_io.StringIO(dec.stdout or "")))[1:]:   # skip header
            if len(row) >= 4:
                p = f"{row[0]}:{row[1]} → {row[2]}:{row[3]}"
                if p not in seen:
                    seen.add(p)
                    paths.append(p)
        count = len(paths)
        return {"available": True, "engine": "codeql",
                "tainted_flow": "yes" if count > 0 else "none_found",
                "flow_count": count, "paths": paths[:3],
                "note": "CodeQL 语义污点分析（精度高）。" + (
                    "" if count > 0 else
                    " 【未发现数据流≠一定安全：可能污点源/汇点定位差一行，或走了动态/框架路径；请 read_file 核实并可换相邻行再查】")}
    except Exception:
        return None
    finally:
        for _f in (src, snk, out):
            try:
                _f.unlink()
            except Exception:
                pass


def _joern_dataflow(root: Path, from_file: str, from_line: int, to_file: str, to_line: int) -> dict:
    ec = _ensure_joern_cpg(root)
    if not ec:
        return {"available": False,
                "note": "数据流引擎不可用（需 Joern + JDK17+）；请用 read_file / check_reachability 人工判断污点。"}
    cpg, joern, java, env = ec
    ff, tf = from_file.replace("\\", "/"), to_file.replace("\\", "/")
    cpg_fwd = str(cpg).replace("\\", "/")
    # per-call unique script → parallel Joern dataflow queries don't clobber one script file.
    tok = hashlib.md5(f"{ff}:{from_line}:{tf}:{to_line}".encode()).hexdigest()[:10]
    script = Path(str(cpg) + f".df_{tok}.sc")
    script.write_text(
        f'importCpg("{cpg_fwd}")\n'
        'run.ossdataflow\n'
        'import io.joern.dataflowengineoss.language._\n'
        'def at(f:String, ln:Int) = cpg.expression'
        '.filter(e => e.lineNumber.exists(_==ln) && e.file.name.exists(_.replace("\\\\","/").endsWith(f)))\n'
        f'val src = at("{ff}", {int(from_line)})\n'
        f'val snk = at("{tf}", {int(to_line)})\n'
        'val flows = snk.reachableByFlows(src).l\n'
        'println("DFCOUNT=" + flows.size)\n'
        'flows.take(3).foreach { fl =>\n'
        '  val hops = fl.elements.map(e => (e.file.name.headOption.getOrElse("?").replace("\\\\","/"))'
        ' + ":" + e.lineNumber.getOrElse(-1)).distinct\n'
        '  println("DFPATH\\t" + hops.mkString(" -> "))\n'
        '}\n', encoding="utf-8")
    try:
        r = subprocess.run(_joern_launch(joern, "joern") + ["--script", str(script)],
                           env=env, capture_output=True, timeout=settings.joern_timeout_sec)
        out = (r.stdout or b"").decode("utf-8", "replace")
    except Exception:
        return {"available": True, "error": "数据流查询超时/失败（该项目可能过大）；请 read_file 人工判断。",
                "note": _note("joern")}
    finally:
        try:
            script.unlink()
        except Exception:
            pass
    count, paths, seen = None, [], set()
    for line in out.splitlines():
        if line.startswith("DFCOUNT="):
            try:
                count = int(line.split("=", 1)[1])
            except Exception:
                count = None
        elif line.startswith("DFPATH\t"):
            p = line.split("\t", 1)[1]
            if p not in seen:
                seen.add(p)
                paths.append(p)
    if count is None:
        return {"available": True, "error": "查询未返回结果（可能端点定位失败）；请核对 file:line。",
                "note": _note("joern")}
    return {"available": True, "engine": "joern",
            "tainted_flow": "yes" if count > 0 else "none_found",
            "flow_count": count, "paths": paths[:3],
            "note": _note("joern") + (
                "" if count > 0 else
                " 【未发现数据流≠安全：Joern 对 Python/JS/PHP 的污点分析较弱，且漏动态派发；请 read_file 人工确认】")}


def _parse_csv(text: str):
    import csv
    import io
    out = []
    rd = csv.reader(io.StringIO(text or ""))
    rows = list(rd)
    for row in rows[1:]:   # skip header
        if len(row) >= 6:
            call_line = row[6] if len(row) >= 7 else "-1"   # call-site line
            out.append((row[0], row[1], row[2], row[3], row[4], row[5], call_line))
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
# On-demand navigation API for the agents (bounded, anchored, engine-labelled).
# Every result carries a note that the graph is STATIC (may miss edges) so the model
# never treats it as an oracle — it navigates with the graph, confirms with the code.
# --------------------------------------------------------------------------- #
def _note(engine: str) -> str:
    return (f"⚠️ 调用图由 {engine} 静态解析生成，可能漏动态派发/框架路由/回调；"
            "结果不保证正确，『不可达/无调用者』也不代表安全——请务必 read_file 核实具体代码。")


def _fmt(g: "Graph", k: tuple) -> str:
    return f"{g.funcs.get(k, {}).get('name', '?')} @ {k[0]}:{k[1]}"


def _resolve(g: "Graph", target: str) -> List[tuple]:
    """Resolve a query target — 'file:line' (preferred, unambiguous) or a function name
    (returns ALL same-named defs so the model disambiguates by location)."""
    t = (target or "").strip().replace("\\", "/")
    if ":" in t and t.rsplit(":", 1)[-1].strip().isdigit():
        f, l = t.rsplit(":", 1)
        k = g.enclosing(f.strip(), int(l.strip()))
        return [k] if k else []
    return list(g.defs_by_name.get(t, []))


def overview(root: Path) -> dict:
    g = get_graph(root)
    if g is None:
        return {"available": False, "note": "调用图不可用，请直接 read_file/search_code。"}
    roots = sorted(g.roots)[:40]
    note = _note(g.engine) + (
        " 【攻击面已截断，仅列前 40】" if len(g.roots) > 40 else
        " 【注意：'攻击面'=图中无内部调用者的函数，可能漏掉框架路由/动态注册的入口，未必完整】")
    return {"available": True, "engine": g.engine, "language": g.lang,
            "functions": len(g.funcs), "edges": sum(len(v) for v in g.edges.values()),
            "attack_surface_total": len(g.roots),
            "attack_surface": [_fmt(g, k) for k in roots],
            "attack_surface_more": max(0, len(g.roots) - 40), "note": note}


def neighbors(root: Path, target: str, direction: str, offset: int = 0, limit: int = 40) -> dict:
    g = get_graph(root)
    if g is None:
        return {"available": False}
    keys = _resolve(g, target)
    if not keys:
        return {"available": True, "found": False,
                "note": "未在调用图中找到该函数（可能是顶层脚本代码、外部库符号、或名称不符）；"
                        "请改用 file:line，或先 read_file 确认函数名后再查。"}
    out = []
    for k in keys:
        if direction == "callees":
            for n in g.edges.get(k, ()):
                cs = g._callsite(k, n)
                out.append(_fmt(g, n) + (f"（调用点 {k[0]}:{cs}）" if cs else "（调用点未知）"))
        else:
            for n in g.redges.get(k, ()):
                cs = g._callsite(n, k)
                out.append(_fmt(g, n) + (f"（在 {n[0]}:{cs} 处调用）" if cs else "（调用点未知）"))
    out = sorted(set(out))
    limit = max(1, min(int(limit or 40), 60))
    offset = max(0, int(offset or 0))
    page = out[offset:offset + limit]
    remaining = max(0, len(out) - offset - len(page))
    note = _note(g.engine) + (
        f" 【分页：本页 {offset}–{offset + len(page)}／共 {len(out)}；还有 {remaining} 条，用 offset={offset + limit} 继续翻】"
        if remaining > 0 else " 【注意：图可能缺边，本清单未必完整，勿据此认定'没有更多'】")
    return {"available": True, "found": True, "target": [_fmt(g, k) for k in keys],
            direction: page, "offset": offset, "shown": len(page), "total": len(out),
            "engine": g.engine, "note": note}


def subgraph(root: Path, around: str, radius: int = 1, limit: int = 60) -> dict:
    """Local neighborhood (callers+callees) within `radius` hops of a function — bounded."""
    g = get_graph(root)
    if g is None:
        return {"available": False}
    keys = _resolve(g, around)
    if not keys:
        return {"available": True, "found": False, "note": "未找到该函数；请用 file:line 或先 read_file。"}
    radius = max(1, min(int(radius or 1), 3))
    limit = max(10, min(int(limit or 60), 100))
    seen, frontier = set(keys), set(keys)
    for _ in range(radius):
        nxt = set()
        for k in frontier:
            nxt |= set(g.edges.get(k, ())) | set(g.redges.get(k, ()))
        nxt -= seen
        seen |= nxt
        frontier = nxt
        if len(seen) >= limit:
            break
    nodeset = set(sorted(seen)[:limit])
    edges = []
    for a in sorted(nodeset):
        for b in g.edges.get(a, ()):
            if b in nodeset:
                cs = g._callsite(a, b)
                edges.append(f"{g.funcs[a]['name']} → {g.funcs[b]['name']}"
                             + (f"（{a[0]}:{cs}）" if cs else ""))
    return {"available": True, "found": True, "center": [_fmt(g, k) for k in keys],
            "radius": radius, "nodes": [_fmt(g, k) for k in sorted(nodeset)],
            "node_count": len(seen), "edges": edges[:80],
            "truncated": len(seen) > limit, "engine": g.engine,
            "note": _note(g.engine) + " 【子图可能缺边/被截断，未必完整】"}


def reachable_query(root: Path, file: str, line: int, entrypoints: List[dict]) -> dict:
    g = get_graph(root)
    if g is None:
        return {"available": False}
    try:
        r = g.reachable(file.replace("\\", "/"), int(line), entrypoints or [])
    except Exception:
        r = None
    if r:
        hops = r.get("path", [])
        chain = " ".join(
            ((f"—(调用点 {h['called_at']})→ " if h.get("called_at") else ("→ " if i else ""))
             + f"{h.get('function', '?')}@{h.get('file')}:{h.get('line')}")
            for i, h in enumerate(hops))
        fanin = r.get("reachable_from_entries", 1)
        note = _note(g.engine)
        if fanin > 1:
            note += f" 【此为最短路径其一，共 {fanin} 个入口可达此点，可能还有其它路径】"
        return {"available": True, "reachable": "yes", "chain": chain,
                "reachable_from_entries": fanin, "entry": r.get("entry_points"),
                "engine": g.engine, "note": note}
    return {"available": True, "reachable": "unconfirmed",
            "detail": "调用图未发现从对外入口到此处的调用链——可能是顶层脚本/动态派发/框架路由，"
                      "【不代表不可达，也不代表安全】，请照常 read_file 核实并按需 report_candidate。",
            "engine": g.engine, "note": _note(g.engine)}


# --------------------------------------------------------------------------- #
# Degradation reporting: which engine actually ran vs the best achievable, + why.
# --------------------------------------------------------------------------- #
_ENGINE_RANK = {"heuristic": 0, "treesitter": 1, "joern": 2, "codeql": 3}
# per-language Joern frontend that shells out to an external interpreter
_JOERN_FRONTEND_TOOL = {"php": "php", "javascript": "node", "typescript": "node", "go": "go"}


def _ideal_engine(lang: str) -> str:
    if lang in _CODEQL_LANG:
        return "codeql"          # bundled query + no build (python, javascript, typescript)
    if lang in ("php", "go", "java", "ruby", "c", "cpp", "csharp"):
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
