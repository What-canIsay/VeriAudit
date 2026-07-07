"""Tool schemas + dispatch for the agents' bounded exploration loop (cloud mode).

These back the LLM function-calling loop (Hunter code exploration, Validator
context gathering). All file access is confined to the project root (path
traversal guard, docs/08). Deterministic analysis primitives live in analysis.py.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

from .. import analysis
from ..knowledge import kb_lookup

# OpenAI/LiteLLM-style tool definitions
TOOL_SCHEMAS: List[dict] = [
    {"type": "function", "function": {
        "name": "list_dir", "description": "列出目录下的文件与子目录（相对项目根）。",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "相对路径，默认根目录"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "read_file", "description": "读取文件内容，可指定起止行。",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "grep", "description": "在代码中用正则检索，快速定位可疑点。",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"}, "max": {"type": "integer"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "kb_search", "description": "检索漏洞知识库（成因/利用手法/修复范式）。",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string"}, "vuln_type": {"type": "string"}}, "required": []}}},
]


def _safe(root: Path, rel: str) -> Path:
    target = (root / (rel or ".")).resolve()
    if not str(target).startswith(str(root.resolve())):
        raise ValueError("path escapes project root")
    return target


def dispatch(root: Path, name: str, args: dict) -> dict:
    try:
        if name == "list_dir":
            d = _safe(root, args.get("path", "."))
            if not d.exists():
                return {"error": "not found"}
            entries = []
            for p in sorted(d.iterdir())[:200]:
                entries.append({"name": p.name, "type": "dir" if p.is_dir() else "file"})
            return {"entries": entries}
        if name == "read_file":
            f = _safe(root, args["path"])
            if not f.is_file():
                return {"error": "not a file"}
            text = analysis.read_text(f)
            lines = text.splitlines()
            start = max(1, int(args.get("start", 1)))
            end = int(args.get("end", min(len(lines), start + 200)))
            chunk = "\n".join(f"{i}: {lines[i-1]}" for i in range(start, min(end, len(lines)) + 1))
            return {"path": args["path"], "lines": len(lines), "content": chunk[:6000]}
        if name == "grep":
            pat = args["pattern"]
            try:
                rx = re.compile(pat)
            except re.error as e:
                return {"error": f"bad regex: {e}"}
            matches = []
            for p, _lang in analysis.iter_source_files(root):
                text = analysis.read_text(p)
                for i, line in enumerate(text.splitlines(), 1):
                    if rx.search(line):
                        matches.append({"file": analysis._rel(root, p), "line": i,
                                        "text": line.strip()[:160]})
                        if len(matches) >= int(args.get("max", 40)):
                            return {"matches": matches}
            return {"matches": matches}
        if name == "kb_search":
            return {"results": kb_lookup(args.get("query", ""), args.get("vuln_type", ""))}
        return {"error": f"unknown tool {name}"}
    except Exception as e:
        return {"error": str(e)[:200]}
