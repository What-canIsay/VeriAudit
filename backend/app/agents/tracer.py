"""Tracer (污点追踪员): 逐候选做 source→sink 污点追踪与可达性判定。"""
from __future__ import annotations

import asyncio

from .. import analysis, callgraph
from ..db import session_scope
from ..models import Candidate
from .context import AuditContext


async def run(ctx: AuditContext) -> dict:
    run_id = await ctx.start_agent("tracer", "trace")
    cands = ctx.state.get("candidates", [])
    entrypoints = ctx.state.get("entrypoints", [])
    reachable_n = 0
    # the call graph was built (and any degradation reported) in Recon; reuse the cache.

    for c in cands:
        # enrich taint source for candidates that lack one (e.g. LLM/scanner-reported),
        # so reachability + dynamic sandbox reproduction can work on them too.
        if c.get("_source") is None:
            await asyncio.to_thread(_enrich_source, ctx.root, c)
        taint = await asyncio.to_thread(analysis.taint_trace, ctx.root, c)
        # laddered reachability: CodeQL > Joern > tree-sitter call graph > file heuristic
        reach = await asyncio.to_thread(callgraph.reachability, ctx.root, c, entrypoints)
        c["taint"] = taint
        c["reachability"] = reach
        c["reachable"] = reach.get("reachable")
        if reach.get("reachable"):
            reachable_n += 1
        if c.get("db_id"):
            with session_scope() as s:
                row = s.get(Candidate, c["db_id"])
                if row:
                    row.taint_path = taint["taint_path"]
                    row.reachability = reach
                    row.reachable = bool(reach.get("reachable"))
        await ctx.log_tool(run_id, "taint_trace+reachability",
                           {"sink": c["location"].get("file")},
                           {"reachable": reach.get("reachable"), "conf": reach.get("confidence"),
                            "engine": reach.get("engine", "heuristic"),
                            "path_len": len(reach.get("path", []) or [])})

    out = {"traced": len(cands), "reachable": reachable_n}
    await ctx.emit("trace.ready", out)
    await ctx.finish_agent(run_id, out)
    return out


def _enrich_source(root, c) -> None:
    try:
        fp = root / c["location"]["file"]
        if not fp.exists():
            return
        text = analysis.read_text(fp)
        lang = analysis.EXT_TO_LANG.get(fp.suffix.lower(), "")
        src, _ = analysis._nearby_source(root, fp, lang, c["location"]["line"],
                                         text.splitlines(), text)
        c["_source"] = src
    except Exception:
        pass
