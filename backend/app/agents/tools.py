"""The LLM-callable toolset — modeled on a real code auditor's workflow.

Design principles (per project requirements):
- The MODEL is the driver. These tools are means it chooses to invoke; the system
  never forces a fixed tool pipeline in cloud mode.
- Each tool has a distinct, non-overlapping purpose — no filler:
    orientation : list_files / read_file / search_code
    attack map  : map_attack_surface        (where untrusted input enters)
    SAST breadth: semgrep_scan               (fast, multi-language, pattern)
    SAST depth  : codeql_scan                (semantic dataflow, precision)
    secrets     : secret_scan                (gitleaks)
    supply chain: dependency_scan            (osv-scanner, SCA)
    manual taint: analyze_dataflow           (targeted source->sink + reachability)
    knowledge   : search_vuln_kb             (cause / exploit / fix recipes)
    commit      : report_candidate           (record a vuln candidate for verification)

Scanner results are cached per task so repeated calls are cheap. File access is
confined to the project root (path-traversal guard, docs/08).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .. import analysis, scanners
from ..knowledge import kb_lookup

TOOL_SCHEMAS: List[dict] = [
    {"type": "function", "function": {
        "name": "list_files", "description": "列出目录结构（相对项目根），用于通读代码组织。",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "read_file", "description": "阅读源码文件内容，可指定起止行。审计前务必先读关键文件。",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "search_code", "description": "正则全局检索代码，快速定位危险函数/关键字/污点源。",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"}, "max": {"type": "integer"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "map_attack_surface", "description": "识别技术栈并枚举对外入口点（HTTP路由/CLI/反序列化点等），即不可信输入进入系统之处。",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "semgrep_scan", "description": "运行 Semgrep 多语言模式 SAST，做快速广度普查，返回候选点列表（含 CWE/位置）。",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "codeql_scan", "description": "运行 CodeQL 语义数据流分析（重、精度高，适合深挖难以判断的数据流漏洞）。",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "secret_scan", "description": "运行 Gitleaks 检测硬编码密钥/凭据。",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "dependency_scan", "description": "运行 OSV-Scanner 检测依赖中的已知 CVE（软件成分分析）。",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "analyze_dataflow", "description": "针对某处代码做 source→sink 污点追踪与可达性判定，用于确认某个可疑点是否真的可被不可信输入触达。",
        "parameters": {"type": "object", "properties": {
            "file": {"type": "string"}, "line": {"type": "integer"}}, "required": ["file", "line"]}}},
    {"type": "function", "function": {
        "name": "cg_overview", "description": "查看审计前已构建的【整项目调用图】概览：引擎、函数/边数、对外入口函数（攻击面）。开挖前先摸清结构。",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "cg_callers", "description": "查【谁调用了】目标函数（反向），结果带调用点行号。target 用 'file:line'（推荐）或函数名。超 40 条用 offset 翻页。",
        "parameters": {"type": "object", "properties": {
            "target": {"type": "string"}, "offset": {"type": "integer", "description": "分页偏移，默认0"}},
            "required": ["target"]}}},
    {"type": "function", "function": {
        "name": "cg_callees", "description": "查目标函数【调用了谁】（正向），带调用点行号。超 40 条用 offset 翻页。",
        "parameters": {"type": "object", "properties": {
            "target": {"type": "string"}, "offset": {"type": "integer"}}, "required": ["target"]}}},
    {"type": "function", "function": {
        "name": "cg_reachable", "description": "判断某危险汇聚点 (file,line) 是否能从对外入口经调用链到达，返回 入口→sink 链（带调用点）及有多少入口可达。用于降误报、定位可打点。",
        "parameters": {"type": "object", "properties": {
            "file": {"type": "string"}, "line": {"type": "integer"}}, "required": ["file", "line"]}}},
    {"type": "function", "function": {
        "name": "cg_path", "description": "查两处代码之间的函数调用链（如 入口→sink），带调用点行号。",
        "parameters": {"type": "object", "properties": {
            "from_file": {"type": "string"}, "from_line": {"type": "integer"},
            "to_file": {"type": "string"}, "to_line": {"type": "integer"}},
            "required": ["from_file", "from_line", "to_file", "to_line"]}}},
    {"type": "function", "function": {
        "name": "cg_subgraph", "description": "取某函数周围 radius 跳内的局部调用子图（调用者+被调用者+边），有界。用于快速了解一块代码的调用结构。",
        "parameters": {"type": "object", "properties": {
            "around": {"type": "string", "description": "'file:line' 或函数名"},
            "radius": {"type": "integer", "description": "跳数，1-3，默认1"}}, "required": ["around"]}}},
    {"type": "function", "function": {
        "name": "cg_dataflow", "description": "【污点/数据流,重】判断从疑似污点源(from)到危险汇聚点(to)是否存在真实数据流,并给出流经路径——这是'控制可达'之上更强的'污点真的流到了'。比可达性更准但更慢,请对高价值的 source→sink 对少量使用。from/to 用变量被使用/危险操作发生的那一行(不是函数定义行)。",
        "parameters": {"type": "object", "properties": {
            "from_file": {"type": "string"}, "from_line": {"type": "integer"},
            "to_file": {"type": "string"}, "to_line": {"type": "integer"}},
            "required": ["from_file", "from_line", "to_file", "to_line"]}}},
    {"type": "function", "function": {
        "name": "search_vuln_kb", "description": "检索漏洞知识库（成因、利用手法、修复范式）。",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string"}, "vuln_type": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "report_candidate", "description": "登记一个漏洞候选，供后续独立验证。发现可疑点应尽量多报（高召回），置信度如实标注。",
        "parameters": {"type": "object", "properties": {
            "vuln_type": {"type": "string", "description": "如 'CWE-89 SQL Injection'"},
            "file": {"type": "string"}, "line": {"type": "integer"},
            "confidence": {"type": "number"}, "rationale": {"type": "string"}},
            "required": ["vuln_type", "file", "line", "rationale"]}}},
]

_RULE_KEYWORDS = [
    ("command", "command-injection"), ("os command", "command-injection"),
    ("sql", "sql-injection"), ("path", "path-traversal"), ("traversal", "path-traversal"),
    ("deserial", "deserialization"), ("ssrf", "ssrf"), ("template", "ssti"),
    ("ssti", "ssti"), ("redirect", "open-redirect"), ("xxe", "xxe"), ("xml external", "xxe"),
    ("xss", "xss"), ("cross-site", "xss"), ("eval", "code-injection"),
    ("code injection", "code-injection"), ("secret", "hardcoded-secret"),
    ("credential", "hardcoded-secret"), ("hardcoded", "hardcoded-secret"),
    ("dependency", "vulnerable-dependency"),
]


def _infer_rule(vuln_type: str) -> str:
    v = (vuln_type or "").lower()
    for kw, rid in _RULE_KEYWORDS:
        if kw in v:
            return rid
    return "llm-semantic"


def _safe(root: Path, rel: str) -> Path:
    target = (root / (rel or ".")).resolve()
    if not str(target).startswith(str(root.resolve())):
        raise ValueError("path escapes project root")
    return target


def _cache(ctx, key, fn):
    cache = ctx.state.setdefault("_scan_cache", {})
    if key not in cache:
        cache[key] = fn()
    return cache[key]


def dispatch(ctx, name: str, args: dict) -> dict:
    """Execute a tool. Runs inside a worker thread (blocking IO/subprocess ok)."""
    root: Path = ctx.root
    try:
        if name == "list_files":
            d = _safe(root, args.get("path", "."))
            if not d.exists():
                return {"error": "not found"}
            return {"entries": [{"name": p.name, "type": "dir" if p.is_dir() else "file"}
                                 for p in sorted(d.iterdir())[:200]]}
        if name == "read_file":
            f = _safe(root, args["path"])
            if not f.is_file():
                return {"error": "not a file"}
            lines = analysis.read_text(f).splitlines()
            start = max(1, int(args.get("start", 1)))
            end = int(args.get("end", min(len(lines), start + 220)))
            chunk = "\n".join(f"{i}: {lines[i-1]}" for i in range(start, min(end, len(lines)) + 1))
            return {"path": args["path"], "lines": len(lines), "content": chunk[:7000]}
        if name == "search_code":
            try:
                rx = re.compile(args["pattern"])
            except re.error as e:
                return {"error": f"bad regex: {e}"}
            matches = []
            for p, _lang in analysis.iter_source_files(root):
                for i, line in enumerate(analysis.read_text(p).splitlines(), 1):
                    if rx.search(line):
                        matches.append({"file": analysis._rel(root, p), "line": i, "text": line.strip()[:160]})
                        if len(matches) >= int(args.get("max", 50)):
                            return {"matches": matches}
            return {"matches": matches}
        if name == "map_attack_surface":
            profile = ctx.state.get("profile") or _cache(ctx, "stack", lambda: analysis.detect_stack(root))
            eps = ctx.state.get("entrypoints") or _cache(ctx, "eps", lambda: analysis.find_entrypoints(root))
            return {"languages": profile.get("languages"), "frameworks": profile.get("frameworks"),
                    "entrypoints": [{"file": e["location"]["file"], "line": e["location"]["line"],
                                      "match": e.get("match")} for e in eps[:60]]}
        if name == "semgrep_scan":
            res = _cache(ctx, "semgrep", lambda: scanners.run_semgrep(root))
            return {"engine": "semgrep", "count": len(res), "results": [_slim(c) for c in res[:60]]}
        if name == "codeql_scan":
            langs = list((ctx.state.get("profile") or analysis.detect_stack(root)).get("languages", {}).keys())
            res = _cache(ctx, "codeql", lambda: scanners.run_codeql(root, langs))
            if not res and not scanners.available()["codeql"]:
                return {"engine": "codeql", "available": False,
                        "note": "CodeQL 未安装，无法运行深度数据流分析（可降级用 analyze_dataflow）。"}
            return {"engine": "codeql", "count": len(res), "results": [_slim(c) for c in res[:60]]}
        if name == "secret_scan":
            res = _cache(ctx, "gitleaks", lambda: scanners.run_gitleaks(root))
            return {"engine": "gitleaks", "count": len(res), "results": [_slim(c) for c in res[:40]]}
        if name == "dependency_scan":
            res = _cache(ctx, "osv", lambda: scanners.run_osv(root))
            return {"engine": "osv-scanner", "count": len(res), "results": [_slim(c) for c in res[:40]]}
        if name == "analyze_dataflow":
            f = args["file"]
            line = int(args["line"])
            text = ""
            fp = root / f
            if fp.exists():
                text = analysis.read_text(fp)
            cand = {"rule_id": "adhoc", "location": analysis._loc(root, fp, line, text) if text else
                    {"file": f, "line": line, "function": None, "snippet": ""},
                    "_source": None}
            src, tainted = analysis._nearby_source(root, fp, analysis.EXT_TO_LANG.get(fp.suffix.lower(), ""),
                                                    line, text.splitlines(), text) if text else (None, False)
            cand["_source"] = src
            taint = analysis.taint_trace(root, cand)
            eps = ctx.state.get("entrypoints") or _cache(ctx, "eps", lambda: analysis.find_entrypoints(root))
            reach = analysis.reachability_check(root, cand, eps)
            return {"taint_path": taint["taint_path"], "has_source": taint["has_source"],
                    "reachability": reach}
        if name in ("cg_overview", "cg_callers", "cg_callees", "cg_reachable", "cg_path",
                    "cg_subgraph", "cg_dataflow"):
            from .. import callgraph
            if name == "cg_overview":
                return callgraph.overview(root)
            if name == "cg_callers":
                return callgraph.neighbors(root, args.get("target", ""), "callers", int(args.get("offset", 0)))
            if name == "cg_callees":
                return callgraph.neighbors(root, args.get("target", ""), "callees", int(args.get("offset", 0)))
            if name == "cg_reachable":
                return callgraph.reachable_query(root, args.get("file", ""), int(args.get("line", 0)),
                                                 ctx.state.get("entrypoints", []))
            if name == "cg_subgraph":
                return callgraph.subgraph(root, args.get("around", ""), int(args.get("radius", 1)))
            if name == "cg_dataflow":
                return callgraph.dataflow(root, args["from_file"], int(args["from_line"]),
                                          args["to_file"], int(args["to_line"]))
            return callgraph.call_path(root, args["from_file"], int(args["from_line"]),
                                       args["to_file"], int(args["to_line"]))
        if name == "search_vuln_kb":
            return {"results": kb_lookup(args.get("query", ""), args.get("vuln_type", ""))}
        if name == "report_candidate":
            return _record(ctx, args)
        return {"error": f"unknown tool {name}"}
    except Exception as e:
        return {"error": str(e)[:200]}


def _slim(c: dict) -> dict:
    return {"vuln_type": c.get("vuln_type"), "file": c["location"]["file"],
            "line": c["location"]["line"], "severity": c.get("_severity"),
            "why": c.get("rationale", "")[:160]}


def _record(ctx, args: dict) -> dict:
    file = args["file"]
    line = int(args["line"])
    vt = args["vuln_type"]
    rid = _infer_rule(vt)
    fp = ctx.root / file
    text = analysis.read_text(fp) if fp.exists() else ""
    loc = analysis._loc(ctx.root, fp, line, text) if text else {"file": file, "line": line,
                                                                 "function": None, "snippet": ""}
    cand = {
        "rule_id": rid, "vuln_type": vt, "_severity": _sev_for(rid),
        "origin": "llm", "self_confidence": float(args.get("confidence", 0.55)),
        "rationale": "LLM 发现：" + args.get("rationale", ""),
        "location": loc, "lang": analysis.EXT_TO_LANG.get(fp.suffix.lower(), "unknown"),
        "_source": None, "_sanitized": False,
    }
    cands = ctx.state.setdefault("candidates", [])
    key = (vt, file, line)
    seen = {(c["vuln_type"], c["location"]["file"], c["location"]["line"]) for c in cands}
    if key in seen:
        return {"ok": True, "duplicate": True}
    cands.append(cand)
    from ..events import emit_threadsafe
    emit_threadsafe(ctx.task_id, "candidate.recorded", {
        "vuln_type": vt, "location": loc, "self_confidence": cand["self_confidence"], "origin": "llm"})
    return {"ok": True, "recorded": {"vuln_type": vt, "file": file, "line": line}}


def _sev_for(rid: str) -> str:
    from ..knowledge import rule_by_id
    r = rule_by_id(rid)
    return r["severity"] if r else "high"
