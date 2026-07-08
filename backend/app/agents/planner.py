"""Planner (编排官): 制定审计策略、预算与收敛条件。"""
from __future__ import annotations

import asyncio

from ..config import settings
from ..llm.gateway import llm
from . import prompts
from .context import AuditContext


async def run(ctx: AuditContext) -> dict:
    run_id = await ctx.start_agent("planner", "plan")
    await ctx.think(run_id, "分析目标、确定语言适配器与审计深度、设置预算护栏。")

    depth = ctx.depth
    # budget was computed by the profiler up front (scaled to project complexity);
    # the planner adopts it. Fall back to static settings if the profiler didn't run.
    budget = dict(ctx.state.get("budget") or {})
    if not budget:
        budget = {
            "max_candidates": settings.max_candidates,
            "max_verify": settings.max_verify if depth != "fast" else max(6, settings.max_verify // 2),
            "dynamic_verification": depth in ("standard", "deep") and settings.enable_sandbox,
            "llm_augment": depth in ("standard", "deep"),
        }
    plan = {
        "depth": depth,
        "budget": budget,
        "strategy": "规模自适应预算 → SAST候选池 + LLM高召回发现 → 可达性闸门 → 独立双层验证 → 证据链固化",
    }
    prof = ctx.state.get("profile_metrics") or {}
    if prof.get("tier"):
        plan["scale"] = {"tier": prof["tier"], "complexity": prof.get("complexity")}
    if llm.enabled:
        j = await asyncio.to_thread(
            llm.judge, "planner", prompts.PLANNER,
            f"项目深度档位={depth}。用一句话说明审计重点方向。以 JSON 返回 {{\"focus\": \"...\"}}。")
        if j and j.get("focus"):
            plan["focus"] = j["focus"]

    ctx.state["plan"] = plan
    await ctx.emit("plan.ready", plan)
    await ctx.finish_agent(run_id, {"plan": plan})
    return plan
