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
        m = (prof.get("metrics") or {})
        stack_line = (f"语言分布={m.get('languages')}；入口点≈{m.get('n_entrypoints')}；"
                      f"依赖≈{m.get('n_deps')}；含数据库={m.get('has_db')}；需构建={m.get('needs_build')}；"
                      f"多语言={m.get('polyglot')}")
        j = await asyncio.to_thread(
            llm.judge, "planner", prompts.PLANNER,
            f"审计深度档位={depth}。项目画像：{stack_line}。\n"
            f"请据此给出本次审计的【重点方向】：最值得优先排查的 2-4 类漏洞（结合语言/框架/是否有数据库判断，"
            f"例如 PHP+MySQL 优先 SQL 注入/文件包含/任意文件上传，Node 优先原型污染/命令注入/SSRF，"
            f"Python Web 优先注入/反序列化/SSTI 等），以及最该重点盯的入口或组件类型。"
            f"以 JSON 返回 {{\"focus\": \"一段话，具体、可执行\"}}。")
        if j and j.get("focus"):
            plan["focus"] = j["focus"]

    ctx.state["plan"] = plan
    await ctx.emit("plan.ready", plan)
    await ctx.finish_agent(run_id, {"plan": plan})
    return plan
