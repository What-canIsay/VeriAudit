"""Orchestration engine — the LangGraph-style state machine (docs/02 §2).

Pipeline: planner → recon → hunter → tracer → validator → reporter, with per-phase
persistence, event emission, budget/timeout guardrails. Runs as an asyncio
background task in-process (single-process MVP; swap to a worker queue later).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from . import control, profiler, sandbox, scanners
from .agents import hunter, planner, provisioner, recon, reporter, tracer, validator
from .agents.context import AuditContext
from .config import settings
from .db import session_scope
from .events import emit
from .knowledge import rule_by_id
from .models import AuditTask, Project

_PHASES = ["assess", "plan", "recon", "hunt", "trace", "verify", "report"]


class AuditCancelled(Exception):
    """Raised at a cooperative checkpoint when the user cancelled the task."""


async def _set(task_id: str, **fields) -> dict:
    counts = {}
    with session_scope() as s:
        t = s.get(AuditTask, task_id)
        if t:
            for k, v in fields.items():
                setattr(t, k, v)
            counts = t.counts or {}
    return counts


async def _emit_status(task_id: str, phase: str, status: str) -> None:
    counts = {}
    with session_scope() as s:
        t = s.get(AuditTask, task_id)
        counts = (t.counts or {}) if t else {}
    await emit(task_id, "task.status", {"status": status, "phase": phase, "counts": counts})


async def run_audit(task_id: str) -> None:
    with session_scope() as s:
        t = s.get(AuditTask, task_id)
        if not t:
            return
        depth = t.depth
        proj = s.get(Project, t.project_id)
        root = Path(proj.workspace_path) if proj and proj.workspace_path else None

    if root is None or not root.exists():
        await _set(task_id, status="failed", error="workspace not prepared")
        await emit(task_id, "task.finished", {"error": "workspace not prepared"})
        return

    await _set(task_id, status="running", phase="assess", started_at=datetime.now(timezone.utc))
    await _emit_status(task_id, "assess", "running")

    ctx = AuditContext(task_id, root, depth)
    ctx.control = control.get_or_create(task_id)   # registered at launch; reuse it
    try:
        # Size the project up front → derive every budget/limit from its complexity.
        await _run_profiler(ctx, task_id)
        await _emit_degradations(ctx, depth)
        task_timeout = ctx.state.get("budget", {}).get("task_timeout_sec", settings.task_timeout_sec)
        try:
            await asyncio.wait_for(_pipeline(ctx, task_id), timeout=task_timeout)
            await _set(task_id, status="succeeded", phase="report",
                       finished_at=datetime.now(timezone.utc))
            await _emit_status(task_id, "report", "succeeded")
        except AuditCancelled:
            await _set(task_id, status="cancelled", finished_at=datetime.now(timezone.utc))
            await _emit_status(task_id, ctx.state.get("_phase", "report"), "cancelled")
            await emit(task_id, "task.finished", {"cancelled": True})
            return
        except asyncio.TimeoutError:
            await _set(task_id, status="failed", error="task timeout",
                       finished_at=datetime.now(timezone.utc))
            await emit(task_id, "task.finished", {"error": "timeout"})
            return
        except Exception as e:  # pragma: no cover
            await _set(task_id, status="failed", error=str(e)[:500],
                       finished_at=datetime.now(timezone.utc))
            await emit(task_id, "task.finished", {"error": str(e)[:200]})
            return

        with session_scope() as s:
            t = s.get(AuditTask, task_id)
            counts = (t.counts or {}) if t else {}
        await emit(task_id, "task.finished", {"counts": counts})
    finally:
        # tear down any persistent provisioned environment + drop the control handle
        await asyncio.to_thread(sandbox.stop_persistent, ctx.state.get("env"))
        control.remove(task_id)


def _should_provision(ctx: AuditContext) -> bool:
    if not settings.enable_provisioner or ctx.depth != "deep":
        return False
    if not sandbox.docker_available():
        return False
    return any((rule_by_id(c.get("rule_id", "")) or {}).get("reproducible")
               for c in ctx.state.get("candidates", []))


async def _emit_degradations(ctx: AuditContext, depth: str) -> None:
    """Surface capability fallbacks up front so the UI never looks 'max capability'
    when it isn't (LLM mock / no Docker / missing scanners)."""
    if settings.mock_mode:
        await ctx.degrade("LLM 模型", "当前为 Mock 离线模式（未配置 API Key），使用确定性规则而非真实大模型审计。", "error")
    if not sandbox.docker_available():
        await ctx.degrade("动态沙箱", "Docker 不可用：跳过动态复现与环境搭建，仅给出静态结论。", "warn")
    missing = [k for k, v in scanners.available().items() if not v]
    if missing:
        hint = "（semgrep 缺失将回落 Bandit）" if "semgrep" in missing else ""
        await ctx.degrade("专业扫描器", f"未安装：{', '.join(missing)}{hint}，影响候选召回广度。", "warn")


async def _run_profiler(ctx: AuditContext, task_id: str) -> None:
    run_id = await ctx.start_agent("profiler", "assess")
    await ctx.think(run_id, "评估项目规模与复杂度（文件数/代码行/入口点/语言/依赖/是否需构建·数据库·多服务），据此计算各阶段预算上限。")
    profile, budget = await asyncio.to_thread(profiler.assess, ctx.root, ctx.depth)
    ctx.state["profile_metrics"] = profile
    ctx.state["budget"] = budget
    await ctx.log_tool(run_id, "assess_project", {}, {"tier": profile.get("tier"), "budget": budget})
    await ctx.emit("assess.ready", {"profile": profile, "budget": budget})
    await ctx.finish_agent(run_id, {"tier": profile.get("tier"),
                                    "complexity": profile.get("complexity"), "budget": budget})


async def _pipeline(ctx: AuditContext, task_id: str) -> None:
    await _phase(task_id, "plan", planner.run, ctx)
    await _phase(task_id, "recon", recon.run, ctx)
    await _phase(task_id, "hunt", hunter.run, ctx)
    await _phase(task_id, "trace", tracer.run, ctx)
    if _should_provision(ctx):
        await _phase(task_id, "provision", provisioner.run, ctx)
    await _phase(task_id, "verify", validator.run, ctx)
    await _phase(task_id, "report", reporter.run, ctx)


async def _phase(task_id: str, phase: str, fn, ctx) -> None:
    # cooperative gate at every phase boundary: block while paused, abort on cancel.
    if not await asyncio.to_thread(ctx.control.checkpoint):
        raise AuditCancelled()
    ctx.state["_phase"] = phase
    await _set(task_id, phase=phase)
    await _emit_status(task_id, phase, "running")
    await fn(ctx)


_MAIN_LOOP: "asyncio.AbstractEventLoop | None" = None


def set_loop(loop) -> None:
    global _MAIN_LOOP
    _MAIN_LOOP = loop


def launch(task_id: str) -> None:
    """Fire-and-forget background run (works from loop or threadpool)."""
    control.create(task_id)   # register control up front so pause/cancel work immediately
    try:
        asyncio.get_running_loop().create_task(run_audit(task_id))
    except RuntimeError:
        if _MAIN_LOOP is not None:
            asyncio.run_coroutine_threadsafe(run_audit(task_id), _MAIN_LOOP)
