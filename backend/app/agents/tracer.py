"""Tracer (污点追踪员): 逐候选做 source→sink 污点追踪与可达性判定。"""
from __future__ import annotations

import asyncio

from .. import analysis
from ..db import session_scope
from ..models import Candidate
from .context import AuditContext


async def run(ctx: AuditContext) -> dict:
    run_id = await ctx.start_agent("tracer", "trace")
    cands = ctx.state.get("candidates", [])
    entrypoints = ctx.state.get("entrypoints", [])
    reachable_n = 0

    for c in cands:
        taint = await asyncio.to_thread(analysis.taint_trace, ctx.root, c)
        reach = await asyncio.to_thread(analysis.reachability_check, ctx.root, c, entrypoints)
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
                           {"reachable": reach.get("reachable"), "conf": reach.get("confidence")})

    out = {"traced": len(cands), "reachable": reachable_n}
    await ctx.emit("trace.ready", out)
    await ctx.finish_agent(run_id, out)
    return out
