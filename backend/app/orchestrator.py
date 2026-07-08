"""Orchestration engine — the LangGraph-style state machine (docs/02 §2).

Pipeline: planner → recon → hunter → tracer → validator → reporter, with per-phase
persistence, event emission, budget/timeout guardrails. Runs as an asyncio
background task in-process (single-process MVP; swap to a worker queue later).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from . import sandbox
from .agents import hunter, planner, provisioner, recon, reporter, tracer, validator
from .agents.context import AuditContext
from .config import settings
from .db import session_scope
from .events import emit
from .knowledge import rule_by_id
from .models import AuditTask, Project

_PHASES = ["plan", "recon", "hunt", "trace", "verify", "report"]


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

    await _set(task_id, status="running", phase="plan", started_at=datetime.now(timezone.utc))
    await _emit_status(task_id, "plan", "running")

    ctx = AuditContext(task_id, root, depth)
    try:
        try:
            await asyncio.wait_for(_pipeline(ctx, task_id), timeout=settings.task_timeout_sec)
            await _set(task_id, status="succeeded", phase="report",
                       finished_at=datetime.now(timezone.utc))
            await _emit_status(task_id, "report", "succeeded")
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
        # tear down any persistent provisioned environment
        await asyncio.to_thread(sandbox.stop_persistent, ctx.state.get("env"))


def _should_provision(ctx: AuditContext) -> bool:
    if not settings.enable_provisioner or ctx.depth != "deep":
        return False
    if not sandbox.docker_available():
        return False
    return any((rule_by_id(c.get("rule_id", "")) or {}).get("reproducible")
               for c in ctx.state.get("candidates", []))


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
    await _set(task_id, phase=phase)
    await _emit_status(task_id, phase, "running")
    await fn(ctx)


_MAIN_LOOP: "asyncio.AbstractEventLoop | None" = None


def set_loop(loop) -> None:
    global _MAIN_LOOP
    _MAIN_LOOP = loop


def launch(task_id: str) -> None:
    """Fire-and-forget background run (works from loop or threadpool)."""
    try:
        asyncio.get_running_loop().create_task(run_audit(task_id))
    except RuntimeError:
        if _MAIN_LOOP is not None:
            asyncio.run_coroutine_threadsafe(run_audit(task_id), _MAIN_LOOP)
