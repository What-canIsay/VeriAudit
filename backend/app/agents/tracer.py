"""Tracer (污点追踪员): 确定性【无 LLM】的证据富化阶段。

逐候选补充：启发式污点路径、CodeQL/Joern 语义污点（source→sink 是否真有数据流）、以及调用图可达性。
它【只富化，绝不接受/拒绝】——所有判定都留给验证官。语义污点较重，仅对 deep 档下最重要的一批候选跑
（引擎为 CodeQL/Joern、且候选有已知污点源时），结果缓存，避免为全部候选付出重复算力。
"""
from __future__ import annotations

import asyncio

from .. import analysis, callgraph
from ..config import settings
from ..db import session_scope
from ..knowledge import SEVERITY_ORDER
from ..models import Candidate
from .context import AuditContext


async def run(ctx: AuditContext) -> dict:
    run_id = await ctx.start_agent("tracer", "trace")
    cands = ctx.state.get("candidates", [])
    entrypoints = ctx.state.get("entrypoints", [])
    engine = ctx.state.get("callgraph_engine")
    # pick the (bounded) subset of candidates that get the heavier semantic-taint upgrade.
    sem_cap = _semantic_budget(ctx, engine, cands)
    sem_targets = {id(c) for c in _rank(cands)[:sem_cap]} if sem_cap else set()

    # WARM-UP (serial): build the shared call graph + (if semantic taint will run) the CodeQL
    # DB / Joern CPG and compile the query ONCE, before fanning out. Build locks make this
    # correctness-safe, but warming here also avoids N workers each paying the ~compile cost.
    await asyncio.to_thread(callgraph.get_graph, ctx.root)
    warmed = set()
    if sem_targets:
        first = next((c for c in _rank(cands) if id(c) in sem_targets), None)
        if first is not None:
            await asyncio.to_thread(_compute_one, ctx.root, first, engine, entrypoints, True)
            warmed.add(id(first))

    # PARALLEL (bounded): compute taint + reachability per candidate concurrently. Each worker
    # mutates only ITS OWN candidate dict and reads the shared read-only caches, so results are
    # identical to serial — this is a pure latency win. Concurrency bounds heavy CodeQL/Joern
    # dataflow subprocesses (memory). No DB/events here (see the serial pass below).
    conc = max(1, int(getattr(settings, "tracer_concurrency", 4)))
    sem = asyncio.Semaphore(conc)

    async def work(c):
        if id(c) in warmed:
            return
        async with sem:
            await asyncio.to_thread(_compute_one, ctx.root, c, engine, entrypoints,
                                    id(c) in sem_targets)

    await asyncio.gather(*(work(c) for c in cands))

    # PERSIST + EVENTS (serial): SQLite writes serialized, stable timeline order.
    reachable_n = semantic_n = 0
    for c in cands:
        reach = c.get("reachability", {}) or {}
        taint = c.get("taint", {}) or {}
        if reach.get("reachable"):
            reachable_n += 1
        if taint.get("semantic"):
            semantic_n += 1
        if c.get("db_id"):
            with session_scope() as s:
                row = s.get(Candidate, c["db_id"])
                if row:
                    row.taint_path = taint.get("taint_path")
                    row.reachability = reach
                    row.reachable = bool(reach.get("reachable"))
        await ctx.log_tool(run_id, "taint_trace+reachability",
                           {"sink": c["location"].get("file")},
                           {"reachable": reach.get("reachable"), "conf": reach.get("confidence"),
                            "engine": reach.get("engine", "heuristic"),
                            "semantic": (taint.get("semantic") or {}).get("tainted_flow"),
                            "path_len": len(reach.get("path", []) or [])})

    out = {"traced": len(cands), "reachable": reachable_n, "semantic_taint": semantic_n}
    await ctx.emit("trace.ready", out)
    await ctx.finish_agent(run_id, out)
    return out


def _compute_one(root, c, engine, entrypoints, do_sem: bool) -> None:
    """Deterministic per-candidate enrichment (runs in a worker thread). Mutates ONLY this
    candidate dict; reads shared read-only caches → safe to run concurrently."""
    if c.get("_source") is None:
        _enrich_source(root, c)
    taint = analysis.taint_trace(root, c)
    if do_sem:
        sem = _semantic_taint(root, c, engine)
        if sem:
            taint["semantic"] = sem
    reach = callgraph.reachability(root, c, entrypoints)
    c["taint"] = taint
    c["reachability"] = reach
    c["reachable"] = reach.get("reachable")


def _rank(cands):
    return sorted(cands, key=lambda c: (-SEVERITY_ORDER.get(c.get("_severity", "medium"), 0),
                                        -c.get("self_confidence", 0.0)))


def _semantic_budget(ctx: AuditContext, engine, cands) -> int:
    """Semantic taint is heavy (CodeQL/Joern per source→sink pair). Only worth it in deep
    mode on a precise engine, capped at the triage limit so a big candidate pool can't blow
    the budget. 0 ⇒ skip entirely (heuristic taint + reachability still run for all)."""
    if ctx.depth != "deep" or engine not in ("codeql", "joern"):
        return 0
    tl = ctx.state.get("budget", {}).get("llm_triage_limit", settings.llm_triage_limit)
    return max(4, min(len(cands), int(tl)))


def _semantic_taint(root, c, engine):
    src = c.get("_source") or {}
    sink = c.get("location") or {}
    sf, sl, kf, kl = src.get("file"), src.get("line"), sink.get("file"), sink.get("line")
    if not (sf and sl and kf and kl):
        return None                      # no known source → nothing to prove flow FROM
    try:
        r = callgraph.dataflow(root, sf, int(sl), kf, int(kl))
    except Exception:
        return None
    if not isinstance(r, dict) or not r.get("available"):
        return None
    return {"engine": r.get("engine"), "tainted_flow": r.get("tainted_flow"),
            "flow_count": r.get("flow_count"), "note": r.get("note")}


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
