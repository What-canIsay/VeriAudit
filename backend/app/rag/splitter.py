"""Code-aware splitter for RAG.

Chunks a source file into semantic units the embedder can index:
  · function / method chunks  (tree-sitter, per-language) — the natural unit of audit
  · module chunks             (contiguous top-level regions: imports / config / class
                               fields / routes-at-module-level) via a sliding window
  · window fallback           (files whose grammar we can't parse → plain line windows)

Oversized functions are window-split (with overlap) so nothing is lost to a length cap.
Each chunk carries file:line anchors + lightweight `security_indicators` (regex flags for
dangerous sinks/sources) so the retriever/tool can say WHY a chunk might matter.

Per-file (not whole-project) so the indexer can re-chunk only the files that changed.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .. import analysis

try:
    from tree_sitter_language_pack import get_parser
    _HAS_TS = True
except Exception:  # pragma: no cover
    _HAS_TS = False

# Splitter format version — bump when chunking logic changes so indexes auto-rebuild.
SPLITTER_VERSION = "1.0"

# language → tree-sitter grammar name (mirrors callgraph._TS_LANG)
_TS_LANG = {"python": "python", "javascript": "javascript", "typescript": "typescript",
            "php": "php", "go": "go", "java": "java"}
# nodes we treat as a standalone code chunk (functions / methods)
_FUNC_TYPES = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "method_definition", "generator_function_declaration"},
    "typescript": {"function_declaration", "method_definition", "generator_function_declaration"},
    "php": {"function_definition", "method_declaration"},
    "go": {"function_declaration", "method_declaration"},
    "java": {"method_declaration", "constructor_declaration"},
}

# quick sink/source signals — coarse but cheap; guides attention, never a verdict.
_SEC_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    ("exec/cmd", re.compile(r"\b(os\.system|subprocess|popen|exec\(|eval\(|child_process|Runtime\.exec|shell_exec|proc_open|passthru)", re.I)),
    ("sql", re.compile(r"\b(select\s+.+\s+from|insert\s+into|update\s+.+\s+set|delete\s+from|execute\(|executemany|cursor\.|mysqli_query|->query\(|createQuery)", re.I)),
    ("deserialize", re.compile(r"\b(pickle\.|yaml\.load|marshal\.|unserialize|ObjectInputStream|readObject|Marshal\.load)", re.I)),
    ("file", re.compile(r"\b(open\(|fopen|readFile|writeFile|file_get_contents|file_put_contents|os\.path\.join|Path\(|include\s|require\s|require_once|include_once)", re.I)),
    ("request/input", re.compile(r"\b(request\.(args|form|json|values|GET|POST|cookies|headers|body|params|query)|\$_(GET|POST|REQUEST|COOKIE|SERVER)|req\.(query|body|params)|input\()", re.I)),
    ("ssrf/net", re.compile(r"\b(requests\.(get|post)|urllib|urlopen|http\.client|fetch\(|axios|curl_exec|file_get_contents\(\s*['\"]https?)", re.I)),
    ("template", re.compile(r"\b(render_template_string|Template\(|jinja2|innerHTML|dangerouslySetInnerHTML|v-html|\.html\()", re.I)),
    ("crypto/secret", re.compile(r"\b(md5|sha1|DES|ECB|random\.random|Math\.random|api[_-]?key|secret|password\s*=|token\s*=|private[_-]?key)", re.I)),
    ("auth", re.compile(r"\b(login|authenticate|authorize|session|jwt|is_admin|require_role|permission|@login_required|verify_token)", re.I)),
]


@dataclass
class CodeChunk:
    chunk_id: str
    file: str
    lang: str
    chunk_type: str            # function | module
    name: str
    start_line: int
    end_line: int
    content: str
    security_indicators: List[str] = field(default_factory=list)

    def embed_text(self) -> str:
        """Text handed to the embedder — a compact header (helps semantic match on
        file/name/tags) followed by the code body."""
        tags = ("[" + ",".join(self.security_indicators) + "] ") if self.security_indicators else ""
        return f"{self.file} :: {self.name} ({self.chunk_type}) {tags}\n{self.content}"

    def to_meta(self) -> dict:
        return {"chunk_id": self.chunk_id, "file": self.file, "lang": self.lang,
                "chunk_type": self.chunk_type, "name": self.name,
                "start_line": self.start_line, "end_line": self.end_line,
                "security_indicators": self.security_indicators}


def _cid(file: str, start: int, end: int, name: str) -> str:
    return hashlib.md5(f"{file}:{start}:{end}:{name}".encode("utf-8", "replace")).hexdigest()[:16]


def _sec_indicators(text: str) -> List[str]:
    return [tag for tag, rx in _SEC_PATTERNS if rx.search(text)]


def _node_name(node) -> str:
    n = node.child_by_field_name("name")
    if n is not None:
        try:
            return n.text.decode("utf-8", "replace")
        except Exception:
            return "<anon>"
    for ch in node.children:
        if ch.type in ("identifier", "name", "property_identifier"):
            try:
                return ch.text.decode("utf-8", "replace")
            except Exception:
                return "<anon>"
    return "<anon>"


def _collect_funcs(node, ftypes, out: List[Tuple[int, int, str]]) -> None:
    """Depth-first; emit the OUTERMOST function/method nodes (don't recurse into a
    function body → inner closures stay part of their enclosing chunk; class methods are
    still reached because a class node isn't a function node)."""
    if node.type in ftypes:
        out.append((node.start_point[0] + 1, node.end_point[0] + 1, _node_name(node)))
        return
    for ch in node.children:
        _collect_funcs(ch, ftypes, out)


def _windows(start: int, end: int, max_lines: int, overlap: int):
    """Yield (ws, we, part) covering [start,end]; part=0 when it fits, else 1..N."""
    if end - start + 1 <= max_lines:
        yield (start, end, 0)
        return
    step = max(1, max_lines - overlap)
    part = 1
    ws = start
    while ws <= end:
        we = min(end, ws + max_lines - 1)
        yield (ws, we, part)
        if we >= end:
            break
        ws += step
        part += 1


def _contiguous(sorted_lines: List[int]):
    if not sorted_lines:
        return
    run_start = prev = sorted_lines[0]
    for ln in sorted_lines[1:]:
        if ln == prev + 1:
            prev = ln
            continue
        yield (run_start, prev)
        run_start = prev = ln
    yield (run_start, prev)


def split_file(rel_path: str, lang: str, text: str,
               max_lines: int = 120, overlap: int = 15) -> List[CodeChunk]:
    lines = text.splitlines()
    if not lines:
        return []
    chunks: List[CodeChunk] = []
    covered = set()

    funcs: List[Tuple[int, int, str]] = []
    ts_lang = _TS_LANG.get(lang)
    if ts_lang and _HAS_TS and ts_lang in _FUNC_TYPES:
        try:
            parser = get_parser(ts_lang)
            tree = parser.parse(text.encode("utf-8", "replace"))
            _collect_funcs(tree.root_node, _FUNC_TYPES[ts_lang], funcs)
        except Exception:
            funcs = []

    for s, e, name in funcs:
        s = max(1, s); e = min(len(lines), e)
        for ws, we, part in _windows(s, e, max_lines, overlap):
            body = "\n".join(lines[ws - 1:we])
            nm = name + (f"#part{part}" if part else "")
            chunks.append(CodeChunk(_cid(rel_path, ws, we, nm), rel_path, lang, "function",
                                    nm, ws, we, body, _sec_indicators(body)))
            covered.update(range(ws, we + 1))

    # module chunks: contiguous regions NOT inside any function (imports/config/class fields/
    # module-level routes). Window-split each region.
    uncovered = [i for i in range(1, len(lines) + 1) if i not in covered]
    for rs, re_ in _contiguous(uncovered):
        for ws, we, part in _windows(rs, re_, max_lines, overlap):
            body = "\n".join(lines[ws - 1:we])
            if not body.strip():
                continue
            nm = "<module>" + (f"#part{part}" if part else "")
            chunks.append(CodeChunk(_cid(rel_path, ws, we, nm), rel_path, lang, "module",
                                    nm, ws, we, body, _sec_indicators(body)))

    # nothing parsed and nothing emitted (e.g. binary-ish) → whole-file windows as a floor
    if not chunks and text.strip():
        for ws, we, part in _windows(1, len(lines), max_lines, overlap):
            body = "\n".join(lines[ws - 1:we])
            nm = "<file>" + (f"#part{part}" if part else "")
            chunks.append(CodeChunk(_cid(rel_path, ws, we, nm), rel_path, lang, "module",
                                    nm, ws, we, body, _sec_indicators(body)))
    return chunks


def split_project(root, max_lines: int = 120, overlap: int = 15):
    """Yield (rel_path, content_hash, [CodeChunk]) for every source file. Used for a full
    (re)index; the indexer calls split_file per changed file for incremental updates."""
    for p, lang in analysis.iter_source_files(root):
        try:
            text = analysis.read_text(p)
        except Exception:
            continue
        rel = analysis._rel(root, p)
        h = hashlib.md5(text.encode("utf-8", "replace")).hexdigest()
        yield rel, h, split_file(rel, lang, text, max_lines, overlap)


def file_hash(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", "replace")).hexdigest()
