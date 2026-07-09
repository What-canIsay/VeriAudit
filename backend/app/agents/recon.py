"""Recon (侦察员): 技术栈/框架识别、入口点与攻击面枚举。"""
from __future__ import annotations

import asyncio

from .. import analysis, callgraph, rag
from ..llm.gateway import llm
from . import prompts
from .context import AuditContext


async def run(ctx: AuditContext) -> dict:
    run_id = await ctx.start_agent("recon", "recon")

    await ctx.think(run_id, "识别技术栈与依赖 (detect_stack)。")
    profile = await asyncio.to_thread(analysis.detect_stack, ctx.root)
    await ctx.log_tool(run_id, "detect_stack", {}, {
        "languages": profile["languages"], "frameworks": profile["frameworks"]})

    await ctx.think(run_id, "枚举对外入口点与攻击面 (find_entrypoints)。")
    entrypoints = await asyncio.to_thread(analysis.find_entrypoints, ctx.root)
    await ctx.log_tool(run_id, "find_entrypoints", {}, {"count": len(entrypoints)})

    ctx.state["profile"] = profile
    ctx.state["entrypoints"] = entrypoints

    # pre-build the whole-project cross-procedure call graph so the Hunter can query it
    # on demand (cached; reused by Tracer/Validator). Warn early if it degraded.
    await ctx.think(run_id, "构建整项目跨过程调用图（供漏洞猎手按需查询：cg_overview/cg_callers/check_reachability…）。")
    cg = await asyncio.to_thread(callgraph.status, ctx.root)
    await ctx.log_tool(run_id, "build_callgraph", {"lang": cg["lang"]},
                       {"engine": cg["engine"], "ideal": cg["ideal"]})
    ctx.state["callgraph_engine"] = cg["engine"]
    ctx.state["callgraph_status"] = cg
    if cg["degraded"]:
        await ctx.degrade("调用图精度",
                          f"{cg['lang']} 项目本应命中 {cg['ideal'].upper()}，实际降级为 {cg['engine'].upper()}：{cg['reason']}",
                          "warn")

    # build/refresh the semantic retrieval index (incremental) so the Hunter/Validator can
    # search_code_semantic. Only when a real model drives them (mock mode won't call tools).
    if rag.available() and llm.enabled:
        await ctx.think(run_id, "构建/增量更新项目语义检索索引（供 search_code_semantic 用自然语言定位代码）。")
        rstat = await asyncio.to_thread(rag.index, ctx.root)
        await ctx.log_tool(run_id, "build_rag_index", {"backend": rstat.get("embedder")},
                           {k: rstat.get(k) for k in ("chunks", "reindexed_files", "incremental")})
        rs = await asyncio.to_thread(rag.status, ctx.root)
        ctx.state["rag_status"] = rs
        if rs.get("degraded"):
            await ctx.degrade("语义检索", rs.get("reason") or "RAG 语义检索降级（回落词法）。", "warn")

    summary = None
    if llm.enabled:
        j = await asyncio.to_thread(
            llm.judge, "recon", prompts.RECON,
            f"技术栈：{profile['languages']}，框架：{profile['frameworks']}，"
            f"入口点数量：{len(entrypoints)}。以 JSON 返回 {{\"attack_surface\": \"...\"}}。")
        if j:
            summary = j.get("attack_surface")

    if summary:
        ctx.state["attack_surface"] = summary   # forwarded to the Hunter (not display-only)
    out = {"languages": profile["languages"], "frameworks": profile["frameworks"],
           "entrypoints": len(entrypoints), "attack_surface": summary}
    await ctx.emit("recon.ready", out)
    await ctx.finish_agent(run_id, out)
    return out
