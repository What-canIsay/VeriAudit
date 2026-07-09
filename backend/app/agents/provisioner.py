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
from . import prompts, provision_tools, verify_tools
from .context import AuditContext


async def run(ctx: AuditContext) -> dict:
    run_id = await ctx.start_agent("provisioner", "provision")

    if not sandbox.docker_available():
        await ctx.think(run_id, "Docker 不可用，跳过环境搭建（回落逐候选轻量复现/静态结论）。")
        await ctx.finish_agent(run_id, {"ready": False})
        return {"ready": False}

    lang = _primary_language(ctx)
    runtime = sandbox._runtime_for(lang)
    await ctx.think(run_id, f"启动常驻沙箱容器并载入项目源码（主语言 {lang} → 运行时 {runtime}）…")
    env = await asyncio.to_thread(sandbox.start_persistent, ctx.root, ctx.task_id, lang)
    if not env:
        await ctx.think(run_id, "无法启动常驻容器（基础镜像缺失或 Docker 异常），回落逐候选复现。")
        await ctx.degrade("环境搭建",
                          "无法启动常驻沙箱容器（基础镜像 python:3.11-slim 缺失或 Docker 异常）："
                          "动态复现回落逐候选轻量尝试/静态结论。", "warn")
        await ctx.finish_agent(run_id, {"ready": False})
        return {"ready": False}
    ctx.state["env"] = env
    ctx.state["provision_runtime"] = runtime
    # honest disclosure: node/php get a real deterministic path + full agentic repro; other
    # runtimes (go/java/…) have no deterministic path and rely on the LLM apt-installing +
    # building — flag that so the user isn't misled about dynamic-repro coverage.
    if runtime not in ("python", "node", "php"):
        await ctx.degrade("动态复现覆盖",
                          f"主语言 {lang} 无确定性搭建路径：将尝试由模型自主 apt 安装运行时并构建；"
                          f"若失败则回落静态结论（静态发现能力不受影响）。", "warn")

    # 1) cheap deterministic attempt (zero-token)
    await ctx.think(run_id, "先尝试确定性搭建：检测框架/依赖并启动应用。")
    prov = await asyncio.to_thread(sandbox.deterministic_provision, ctx.root, env)
    if prov.get("ready"):
        await ctx.emit("provision.ready", {"port": prov["port"], "by": "deterministic",
                                           "start": prov.get("start")})
        await _maybe_preheat(ctx, run_id, env)
        await ctx.finish_agent(run_id, {"ready": True, "port": env["port"], "by": "deterministic"})
        return {"ready": True, "port": env["port"]}

    # 2) LLM-driven provisioning (bounded)
    if llm.enabled:
        await ctx.think(run_id, f"确定性搭建未就绪（{prov.get('reason')}），转由模型自主搭建（读配方/装依赖/建库/启动）。")
        await asyncio.to_thread(_llm_provision, ctx, run_id, env)

    if env.get("ready"):
        await ctx.emit("provision.ready", {"port": env["port"], "by": "llm"})
        await _maybe_preheat(ctx, run_id, env)
        out = {"ready": True, "port": env["port"], "by": "llm"}
    else:
        reason = env.get("gaveup") or prov.get("reason") or "未就绪"
        await ctx.emit("provision.failed", {"reason": reason})
        await ctx.degrade("环境搭建", f"未能把目标应用搭起来（{reason}）：动态复现将回落逐候选轻量尝试/静态结论。", "warn")
        out = {"ready": False}
    await ctx.finish_agent(run_id, out)
    return out


async def _maybe_preheat(ctx: AuditContext, run_id, env: dict) -> None:
    """After the app is up, run an LLM-driven, project-specific preheat so per-candidate
    verification starts warm (test accounts, logged-in role sessions, seeded data, memo).
    Subsumes the old DB-seeding enrichment."""
    if not (settings.enable_provisioner_preheat and llm.enabled):
        return
    await ctx.think(run_id, "核验预热：按本项目自适应地准备可复用的测试账号/角色会话/数据，供后续逐个漏洞核验复用。")
    await asyncio.to_thread(_preheat, ctx, run_id, env)
    if ctx.state.get("verify_setup"):
        await ctx.emit("preheat.ready", {"sessions": list((ctx.state.get("verify_sessions") or {}).keys())})


def _primary_language(ctx: AuditContext) -> str:
    """Dominant source language from Recon's stack detection (languages is a count dict,
    already sorted desc). Drives which runtime we stand the app up with."""
    langs = (ctx.state.get("profile", {}) or {}).get("languages") or {}
    if isinstance(langs, dict) and langs:
        return max(langs, key=langs.get)
    if isinstance(langs, list) and langs:
        return langs[0]
    return "python"


def _needs_db_enrich(ctx: AuditContext) -> bool:
    return any(c.get("rule_id") == "sql-injection" for c in ctx.state.get("candidates", []))


def _preheat(ctx: AuditContext, run_id, env: dict) -> None:
    budget = ctx.state.get("budget", {})
    deadline = time.time() + budget.get("provisioner_timeout_sec", settings.provisioner_timeout_sec)
    result: dict = {}
    user = (f"应用已在端口 {env.get('port')} 运行（基础路径 '{env.get('base_path', '')}'）。"
            "请阅读本项目、判断后续漏洞核验会需要什么，并据此做好可复用准备（测试账号/角色会话/数据）。"
            "完成后调用 preheat_ready。")

    def on_step(reasoning, content, tool_names):
        ctx.emit_reasoning_sync(run_id, reasoning=reasoning,
                                output=(content if content and not tool_names else None), kind="provision")

    def on_tool(name, args, res):
        if name == "preheat_ready":
            result.update(args or {})
        summ = {k: res.get(k) for k in ("exit_code", "status", "ok", "note")
                if isinstance(res, dict) and k in res}
        ctx.log_tool_sync(run_id, name, args, summ or {"via": "preheat"},
                          ok="error" not in (res or {}))

    def dispatch(n, a):
        if time.time() > deadline:
            return {"error": "预热时间预算耗尽 — 请调用 preheat_ready 登记已完成的准备。"}
        return verify_tools.dispatch(env, ctx, n, a)

    finalize_hint = "预算即将用尽，请立即 preheat_ready 登记已完成的准备（若本项目无需准备也调用并说明）。"
    try:
        llm.agentic("provisioner", prompts.PREHEAT, user, verify_tools.PREHEAT_SCHEMAS, dispatch,
                    on_tool=on_tool, on_step=on_step,
                    max_steps=budget.get("preheat_max_steps", settings.preheat_max_steps),
                    stop_tools={"preheat_ready"}, finalize_hint=finalize_hint, finalize_at=2,
                    timeout=budget.get("llm_timeout_sec"), num_retries=budget.get("llm_num_retries"))
    except Exception:
        pass
    if result.get("memo"):
        ctx.state["verify_setup"] = str(result["memo"])[:1500]
    if isinstance(result.get("sessions"), dict):
        ctx.state["verify_sessions"] = result["sessions"]


def _llm_provision(ctx: AuditContext, run_id, env: dict, enrich: bool = False) -> None:
    budget = ctx.state.get("budget", {})
    deadline = time.time() + budget.get("provisioner_timeout_sec", settings.provisioner_timeout_sec)
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

    finalize_hint = ("步数/时间预算即将用尽。若应用已可访问：立刻 check_ready 确认后 mark_ready(端口)；"
                     "若确实起不来：立刻 give_up 并简述原因。不要再尝试新的安装/下载方案。")
    try:
        llm.agentic("provisioner", prompts.PROVISIONER, user,
                    provision_tools.TOOL_SCHEMAS, dispatch, on_tool=on_tool, on_step=on_step,
                    max_steps=budget.get("provisioner_max_steps", settings.provisioner_max_steps),
                    stop_tools={"mark_ready", "give_up"},
                    finalize_hint=finalize_hint, finalize_at=3,
                    timeout=budget.get("llm_timeout_sec"), num_retries=budget.get("llm_num_retries"))
    except Exception:
        pass
