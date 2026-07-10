"""Deterministic analysis engine: candidate discovery + taint + reachability.

This engine encodes the "SAST-as-candidate-generator" half of the design. It is
used directly in mock mode and exposed to the LLM agents as tools (grep/ast/taint
/reachability) in cloud mode. It is intentionally heuristic but produces real,
inspectable evidence chains (source -> hops -> sink) across multiple languages.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .knowledge import (EXT_TO_LANG, LANGUAGE_ADAPTERS, SOURCES, VULN_RULES,
                        rule_by_id)

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
              "build", ".idea", ".vscode", "vendor", "target", ".next"}
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 4000


def iter_source_files(root: Path):
    count = 0
    for p in root.rglob("*"):
        if count >= _MAX_FILES:
            break
        if p.is_dir():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        lang = EXT_TO_LANG.get(p.suffix.lower())
        if not lang:
            continue
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        count += 1
        yield p, lang


def read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Project profiling
# --------------------------------------------------------------------------- #
def detect_stack(root: Path) -> dict:
    langs: Dict[str, int] = {}
    for p, lang in iter_source_files(root):
        langs[lang] = langs.get(lang, 0) + 1
    frameworks: List[str] = []
    deps: Dict[str, List[str]] = {}
    for lang, adapter in LANGUAGE_ADAPTERS.items():
        for man in adapter["manifest"]:
            mf = root / man
            if mf.exists():
                text = read_text(mf)
                deps[man] = _extract_deps(man, text)
                frameworks.extend(_guess_frameworks(text))
    return {
        "languages": dict(sorted(langs.items(), key=lambda kv: -kv[1])),
        "frameworks": sorted(set(frameworks)),
        "deps": deps,
    }


def _extract_deps(manifest: str, text: str) -> List[str]:
    out: List[str] = []
    if manifest == "requirements.txt":
        out = [ln.split("==")[0].strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    elif manifest == "package.json":
        out = re.findall(r'"([\w@/\-]+)"\s*:', text)
    return out[:100]


def _guess_frameworks(text: str) -> List[str]:
    fw = []
    for name in ["flask", "django", "fastapi", "express", "react", "gin", "spring", "laravel"]:
        if re.search(rf"\b{name}\b", text, re.I):
            fw.append(name)
    return fw


def find_entrypoints(root: Path) -> List[dict]:
    eps: List[dict] = []
    for p, lang in iter_source_files(root):
        patterns = LANGUAGE_ADAPTERS[lang]["entrypoints"]
        text = read_text(p)
        for i, line in enumerate(text.splitlines(), 1):
            for pat in patterns:
                if re.search(pat, line):
                    eps.append({"kind": "route/handler", "location": _loc(root, p, i, text),
                                 "lang": lang, "match": line.strip()[:120]})
                    break
        if len(eps) > 300:
            break
    return eps


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(p).replace("\\", "/")


_FUNC_RE = re.compile(r"^\s*(?:def|function|func|sub|public|private|protected|static|async)?\s*"
                      r"(?:function\s+)?([A-Za-z_]\w*)\s*\(")


def _enclosing_function(lines: List[str], idx: int) -> Optional[str]:
    for j in range(idx, -1, -1):
        m = re.match(r"\s*(?:async\s+)?def\s+([A-Za-z_]\w*)", lines[j]) or \
            re.match(r"\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_]\w*)", lines[j]) or \
            re.match(r"\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)", lines[j]) or \
            re.match(r"\s*(?:public|private|protected|static|final|\s)+[\w<>\[\]]+\s+([A-Za-z_]\w*)\s*\(", lines[j])
        if m:
            return m.group(1)
    return None


def _snippet(lines: List[str], idx: int, ctx: int = 1) -> str:
    a = max(0, idx - ctx)
    b = min(len(lines), idx + ctx + 1)
    return "\n".join(lines[a:b])


def _loc(root: Path, p: Path, line: int, text: str) -> dict:
    lines = text.splitlines()
    idx = line - 1
    return {
        "file": _rel(root, p), "line": line,
        "function": _enclosing_function(lines, idx) if 0 <= idx < len(lines) else None,
        "snippet": _snippet(lines, idx) if 0 <= idx < len(lines) else "",
    }


# --------------------------------------------------------------------------- #
# Candidate discovery (regex sink matching over knowledge base)
# --------------------------------------------------------------------------- #
def scan_candidates(root: Path) -> List[dict]:
    candidates: List[dict] = []
    seen = set()
    for p, lang in iter_source_files(root):
        text = read_text(p)
        if not text:
            continue
        lines = text.splitlines()
        for rule in VULN_RULES:
            sink_pats = rule["sinks"].get(lang, []) + rule["sinks"].get("*", [])
            for pat in sink_pats:
                try:
                    rx = re.compile(pat)
                except re.error:
                    continue
                for i, line in enumerate(lines, 1):
                    if rx.search(line):
                        key = (rule["id"], _rel(root, p), i)
                        if key in seen:
                            continue
                        seen.add(key)
                        candidates.append(_make_candidate(root, p, lang, rule, i, lines, text))
    # sort by severity then confidence
    from .knowledge import SEVERITY_ORDER
    candidates.sort(key=lambda c: (-SEVERITY_ORDER.get(c["_severity"], 0), -c["self_confidence"]))
    return candidates


def _make_candidate(root: Path, p: Path, lang: str, rule: dict, line: int,
                    lines: List[str], text: str) -> dict:
    loc = _loc(root, p, line, text)
    # heuristic: does an untrusted source appear near the sink?
    src_loc, tainted = _nearby_source(root, p, lang, line, lines, text)
    conf = 0.55
    if tainted:
        conf += 0.2
    # sanitizer presence lowers confidence
    sanitized = _has_sanitizer(rule, lang, src_loc["line"] if src_loc else line, line, lines)
    if sanitized:
        conf -= 0.25
    return {
        "rule_id": rule["id"],
        "vuln_type": f"{rule['cwe']} {rule['name']}",
        "_severity": rule["severity"],
        "origin": "regex",
        "self_confidence": round(max(0.1, min(0.95, conf)), 2),
        "rationale": (f"匹配到 {rule['name']} 危险汇聚点；"
                       + ("同函数/邻近发现不可信输入，疑似污点可达。" if tainted else "未在邻近发现明确污点源，需追踪确认。")
                       + ("检测到疑似净化器，置信度下调。" if sanitized else "")),
        "location": loc,
        "lang": lang,
        "_source": src_loc,
        "_sanitized": sanitized,
    }


# --------------------------------------------------------------------------- #
# Framework-aware LOGIC-vuln heuristics (missing-auth / IDOR / CSRF).
# These "missing check" bugs have no dangerous-sink regex, so we detect them structurally
# using each framework's markers (knowledge_frameworks): a state-changing route with no auth
# marker in its body/file → missing-auth seed; an object-fetch-by-id with no ownership marker
# nearby → IDOR seed; a state-changing route in a CSRF-default-off framework with no CSRF
# marker → CSRF seed. Deliberately HIGH-RECALL / low-confidence — the Validator prunes them.
# --------------------------------------------------------------------------- #
_CSRF_DEFAULT_OFF = {"flask", "fastapi", "express", "gin"}


def _any_re(pats, text: str) -> bool:
    for p in pats or ():
        try:
            if re.search(p, text):
                return True
        except re.error:
            pass
    return False


def _merge_markers(records: List[dict]) -> dict:
    keys = ("route", "method_post", "auth", "object_by_id", "ownership", "csrf")
    out = {k: [] for k in keys}
    for r in records:
        for k in keys:
            out[k] += r.get("markers", {}).get(k, [])
    return out


def _enclosing_handler(lines: List[str], i: int, route_pats, max_span: int = 60) -> str:
    """Text of the route-handler enclosing 1-indexed line `i`, bounded by the surrounding
    route declarations so a marker in the NEXT handler can't leak in (that was suppressing
    real seeds). Includes a couple of decorator lines above the handler's route line."""
    n = len(lines)
    s = i - 1                                   # 0-indexed line i
    steps = 0
    while s > 0 and steps < max_span and not _any_re(route_pats, lines[s]):
        s -= 1; steps += 1
    start = max(0, s - 2)                        # a few decorator lines above the route
    e = i                                        # scan down to the NEXT handler's route line
    steps = 0
    while e < n and steps < max_span and not _any_re(route_pats, lines[e]):
        e += 1; steps += 1
    return "\n".join(lines[start:e])


def scan_logic_candidates(root: Path, frameworks: List[str], cap: int = 40) -> List[dict]:
    from .knowledge_frameworks import FRAMEWORKS, _ALIASES
    recs = []
    for fw in frameworks or []:
        key = _ALIASES.get((fw or "").lower(), (fw or "").lower())
        if key in FRAMEWORKS and FRAMEWORKS[key] not in recs:
            recs.append(FRAMEWORKS[key])
    if not recs:
        return []
    out: List[dict] = []
    for p, lang in iter_source_files(root):
        fw = [r for r in recs if r["language"] == lang]
        if not fw:
            continue
        text = read_text(p)
        if not text:
            continue
        lines = text.splitlines()
        m = _merge_markers(fw)
        file_csrf = _any_re(m["csrf"], text)   # CSRF setup is usually app/file-level
        csrf_off = any((r["name"].split()[0].lower() in _CSRF_DEFAULT_OFF) for r in fw)
        for i, line in enumerate(lines, 1):
            if _any_re(m["method_post"], line):                 # state-changing route
                window = _enclosing_handler(lines, i, m["route"])
                if not _any_re(m["auth"], window):
                    out.append(_logic_cand(root, p, lang, "missing-authentication", i, lines, text,
                                           "状态变更路由未见鉴权守卫（该处理器内无 auth 标记）"))
                if csrf_off and not (file_csrf or _any_re(m["csrf"], window)):
                    out.append(_logic_cand(root, p, lang, "csrf", i, lines, text,
                                           "状态变更路由；该框架默认无 CSRF 且未见 CSRF 校验"))
            if _any_re(m["object_by_id"], line):                # fetch object by request id
                window = _enclosing_handler(lines, i, m["route"])
                if not _any_re(m["ownership"], window):
                    out.append(_logic_cand(root, p, lang, "broken-access-control", i, lines, text,
                                           "按 id 取对象但该处理器内未见归属/所有权校验（疑似 IDOR）"))
            if len(out) >= cap:
                return out
    return out


def _logic_cand(root: Path, p: Path, lang: str, rule_id: str, line: int,
                lines: List[str], text: str, why: str) -> dict:
    from .knowledge import rule_by_id
    rule = rule_by_id(rule_id) or {}
    loc = _loc(root, p, line, text)
    src_loc, _tainted = _nearby_source(root, p, lang, line, lines, text)
    return {
        "rule_id": rule_id,
        "vuln_type": f"{rule.get('cwe', '')} {rule.get('name', rule_id)}",
        "_severity": rule.get("severity", "medium"),
        "origin": "logic-heuristic",
        "self_confidence": 0.35,   # low: a high-recall seed the Validator confirms/rejects
        "rationale": f"框架感知启发式：{why}（低置信度种子，待验证官核实）。",
        "location": loc,
        "lang": lang,
        "_source": src_loc,
        "_sanitized": False,
    }


def _nearby_source(root: Path, p: Path, lang: str, sink_line: int,
                   lines: List[str], text: str) -> Tuple[Optional[dict], bool]:
    pats = SOURCES.get(lang, [])
    lo = max(0, sink_line - 40)
    hi = min(len(lines), sink_line + 5)
    for i in range(lo, hi):
        for pat in pats:
            if re.search(pat, lines[i]):
                return _loc(root, p, i + 1, text), True
    return None, False


def _has_sanitizer(rule: dict, lang: str, start: int, end: int, lines: List[str]) -> bool:
    pats = rule.get("sanitizers", {}).get(lang, [])
    a, b = min(start, end) - 1, max(start, end)
    a = max(0, a)
    for i in range(a, min(len(lines), b + 1)):
        for pat in pats:
            if re.search(pat, lines[i]):
                return True
    return False


# --------------------------------------------------------------------------- #
# Taint tracing + reachability (Tracer)
# --------------------------------------------------------------------------- #
def taint_trace(root: Path, candidate: dict) -> dict:
    """Build source -> sink taint path (heuristic, intra-file)."""
    sink = candidate["location"]
    src = candidate.get("_source")
    hops: List[dict] = []
    if src:
        hops.append({"location": src, "variable": "user_input",
                      "transform": "来自不可信输入", "note": "污点源"})
        # intermediate: same function assignments (best-effort, 1 synthetic hop)
        if src["line"] < sink["line"]:
            hops.append({"location": {"file": sink["file"], "line": (src["line"] + sink["line"]) // 2,
                                        "function": sink.get("function")},
                          "variable": "tainted", "transform": "传播/拼接", "note": "污点在函数内传播"})
    hops.append({"location": sink, "variable": "tainted", "transform": "进入危险汇聚点", "note": "污点汇聚"})
    return {
        "taint_path": hops,
        "sanitizers": ([{"name": "疑似净化器", "effective": True, "location": sink}]
                        if candidate.get("_sanitized") else []),
        "has_source": bool(src),
    }


def reachability_check(root: Path, candidate: dict, entrypoints: List[dict]) -> dict:
    sink = candidate["location"]
    file = sink["file"]
    ep_in_file = [e for e in entrypoints if e["location"]["file"] == file]
    has_source = candidate.get("_source") is not None
    if ep_in_file:
        return {"reachable": True, "confidence": 0.8, "preconditions": [],
                "entry_points": [e["location"] for e in ep_in_file[:3]],
                "note": "sink 所在文件存在对外入口点"}
    if has_source:
        return {"reachable": True, "confidence": 0.6, "preconditions": [],
                "entry_points": [candidate["_source"]],
                "note": "sink 邻近存在不可信输入源，判定条件可达"}
    return {"reachable": None, "confidence": 0.35, "preconditions": ["需确认调用链"],
            "entry_points": [], "note": "未能确认从对外入口点到 sink 的调用路径"}


# --------------------------------------------------------------------------- #
# Optional Semgrep integration (graceful degradation)
# --------------------------------------------------------------------------- #
def run_semgrep(root: Path) -> List[dict]:
    if not shutil.which("semgrep"):
        return []
    try:
        r = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "--quiet", "--timeout", "60", str(root)],
            capture_output=True, text=True, timeout=240,
        )
        import json as _json
        data = _json.loads(r.stdout or "{}")
    except Exception:
        return []
    out: List[dict] = []
    for res in data.get("results", [])[:100]:
        path = res.get("path", "")
        line = res.get("start", {}).get("line", 1)
        extra = res.get("extra", {})
        out.append({
            "rule_id": "semgrep", "origin": "sast", "self_confidence": 0.7,
            "vuln_type": extra.get("metadata", {}).get("cwe", ["CWE-Unknown"])[0]
                if isinstance(extra.get("metadata", {}).get("cwe"), list) else "SAST Finding",
            "_severity": (extra.get("severity", "medium") or "medium").lower(),
            "rationale": extra.get("message", "Semgrep rule match"),
            "location": {"file": _rel(root, Path(path)) if Path(path).is_absolute() else path,
                          "line": line, "function": None, "snippet": extra.get("lines", "")},
            "lang": EXT_TO_LANG.get(Path(path).suffix.lower(), "unknown"),
            "_source": None, "_sanitized": False,
        })
    return out
