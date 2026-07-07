"""Recon (侦察员): 技术栈/框架识别、入口点与攻击面枚举。"""
from __future__ import annotations

import asyncio

from .. import analysis
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

    summary = None
    if llm.enabled:
        j = await asyncio.to_thread(
            llm.judge, "recon", prompts.RECON,
            f"技术栈：{profile['languages']}，框架：{profile['frameworks']}，"
            f"入口点数量：{len(entrypoints)}。以 JSON 返回 {{\"attack_surface\": \"...\"}}。")
        if j:
            summary = j.get("attack_surface")

    out = {"languages": profile["languages"], "frameworks": profile["frameworks"],
           "entrypoints": len(entrypoints), "attack_surface": summary}
    await ctx.emit("recon.ready", out)
    await ctx.finish_agent(run_id, out)
    return out
