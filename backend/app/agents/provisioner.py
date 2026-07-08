"""Provisioner (环境构建官): stand the target app up ONCE in a persistent sandbox
container, so the Validator can fire real PoCs at it and reuse it across all
candidates. Cheap deterministic attempt first; LLM-driven improvisation on failure,
bounded by step/time budgets + repeated-command circuit breaker (anti token-loop).
"""
from __future__ import annotations

import asyncio
import time

from .. import sandbox
from ..config import settings
from ..llm.gateway import llm
from . import prompts, provision_tools
from .context import AuditContext


async def run(ctx: AuditContext) -> dict:
    run_id = await ctx.start_agent("provisioner", "provision")

    if not sandbox.docker_available():
        await ctx.think(run_id, "Docker 不可用，跳过环境搭建（回落逐候选轻量复现/静态结论）。")
        await ctx.finish_agent(run_id, {"ready": False})
        return {"ready": False}

    await ctx.think(run_id, "启动常驻沙箱容器并载入项目源码…")
    env = await asyncio.to_thread(sandbox.start_persistent, ctx.root, ctx.task_id, "python")
    if not env:
        await ctx.think(run_id, "无法启动常驻容器（当前仅支持 Python 项目 / 基础镜像缺失），回落逐候选复现。")
        await ctx.finish_agent(run_id, {"ready": False})
        return {"ready": False}
    ctx.state["env"] = env

    # 1) cheap deterministic attempt (zero-token)
    await ctx.think(run_id, "先尝试确定性搭建：检测框架/依赖并启动应用。")
    prov = await asyncio.to_thread(sandbox.deterministic_provision, ctx.root, env)
    if prov.get("ready"):
        await ctx.emit("provision.ready", {"port": prov["port"], "by": "deterministic",
                                           "start": prov.get("start")})
        # optional LLM enrichment: seed/migrate the DB so DB-backed vulns reproduce
        if settings.provisioner_llm_enrich and llm.enabled and _needs_db_enrich(ctx):
            await ctx.think(run_id, "应用已就绪；进一步由模型建表/迁移/seed 数据库，以支持数据库相关漏洞的动态复现。")
            await asyncio.to_thread(_llm_provision, ctx, run_id, env, True)
        await ctx.finish_agent(run_id, {"ready": True, "port": env["port"], "by": "deterministic"})
        return {"ready": True, "port": env["port"]}

    # 2) LLM-driven provisioning (bounded)
    if llm.enabled:
        await ctx.think(run_id, f"确定性搭建未就绪（{prov.get('reason')}），转由模型自主搭建（读配方/装依赖/建库/启动）。")
        await asyncio.to_thread(_llm_provision, ctx, run_id, env)

    if env.get("ready"):
        await ctx.emit("provision.ready", {"port": env["port"], "by": "llm"})
        out = {"ready": True, "port": env["port"], "by": "llm"}
    else:
        await ctx.emit("provision.failed", {"reason": env.get("gaveup") or prov.get("reason") or "未就绪"})
        out = {"ready": False}
    await ctx.finish_agent(run_id, out)
    return out


def _needs_db_enrich(ctx: AuditContext) -> bool:
    return any(c.get("rule_id") == "sql-injection" for c in ctx.state.get("candidates", []))


def _llm_provision(ctx: AuditContext, run_id, env: dict, enrich: bool = False) -> None:
    deadline = time.time() + settings.provisioner_timeout_sec
    if enrich:
        user = (f"应用已在端口 {env.get('port')} 运行。为了能对数据库相关漏洞（如 SQL 注入）进行真实动态复现，"
                "请确保数据库可用：阅读代码判断所用数据库与表结构，用 run_command 创建/迁移表并插入若干示例数据(seed)；"
                "若应用在启动时缓存了连接，必要时先结束旧进程再用 start_app 重启。完成后 mark_ready(端口)。"
                "请高效，无法完成就 give_up，不要反复打转。")
    else:
        user = ("请让本项目在沙箱里跑起来（应用端口可访问）。优先使用项目自带的搭建配方"
                "（docker-compose / Dockerfile / CI 工作流 / README / Makefile / 框架约定）。"
                "需要数据库/迁移/seed/环境变量时，用 run_command 完成；用 start_app 启动；"
                "check_ready 确认后 mark_ready(端口)。起不来就尽快 give_up。请高效，不要在同一错误上反复打转。")

    def on_step(reasoning, content, tool_names):
        ctx.emit_reasoning_sync(run_id, reasoning=reasoning,
                                output=(content if content and not tool_names else None), kind="provision")

    def on_tool(name, args, result):
        summ = {k: result.get(k) for k in ("exit_code", "up", "ready", "started", "ok", "note")
                if isinstance(result, dict) and k in result}
        ctx.log_tool_sync(run_id, name, args, summ or {"via": "prov"},
                          ok=(result or {}).get("exit_code", 0) != -1)

    def dispatch(n, a):
        if time.time() > deadline:
            return {"error": "provisioning time budget exhausted — 请调用 give_up。"}
        return provision_tools.dispatch(env, ctx, n, a)

    try:
        llm.agentic("provisioner", prompts.PROVISIONER, user,
                    provision_tools.TOOL_SCHEMAS, dispatch, on_tool=on_tool, on_step=on_step,
                    max_steps=settings.provisioner_max_steps,
                    stop_tools={"mark_ready", "give_up"})
    except Exception:
        pass
