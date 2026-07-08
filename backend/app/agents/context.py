"""Shared execution context passed to every agent node."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..db import session_scope
from ..events import emit as bus_emit
from ..events import emit_threadsafe
from ..models import AgentRun, ToolInvocation


class AuditContext:
    def __init__(self, task_id: str, root: Path, depth: str) -> None:
        self.task_id = task_id
        self.root = root
        self.depth = depth
        self.state: Dict[str, Any] = {
            "profile": {}, "entrypoints": [], "candidates": [], "findings": [],
            "rejected": [], "notes": [],
        }
        self.current_agent = "system"

    async def emit(self, event: str, data: dict) -> None:
        await bus_emit(self.task_id, event, data)

    async def start_agent(self, agent: str, node: str) -> str:
        self.current_agent = agent
        run_id = None
        with session_scope() as s:
            run = AgentRun(task_id=self.task_id, agent=agent, node=node, status="running")
            s.add(run)
            s.flush()
            run_id = run.id
        await self.emit("agent.started", {"agent": agent, "node": node, "run_id": run_id})
        return run_id

    async def finish_agent(self, run_id: str, output: dict) -> None:
        with session_scope() as s:
            run = s.get(AgentRun, run_id)
            if run:
                run.status = "completed"
                run.output = output
                run.finished_at = datetime.now(timezone.utc)
        await self.emit("agent.finished", {"run_id": run_id, "output": output})

    async def log_tool(self, run_id: Optional[str], tool: str, args: dict,
                       summary: dict, ok: bool = True) -> None:
        with session_scope() as s:
            s.add(ToolInvocation(task_id=self.task_id, agent_run_id=run_id,
                                 agent=self.current_agent, tool=tool, args=args,
                                 result_summary=summary, ok=ok))
        await self.emit("tool.invoked", {"run_id": run_id, "agent": self.current_agent,
                                          "tool": tool, "args_brief": _brief(args)})
        await self.emit("tool.result", {"run_id": run_id, "tool": tool, "ok": ok,
                                        "summary": summary})

    async def think(self, run_id: Optional[str], text: str) -> None:
        await self.emit("agent.thinking", {"run_id": run_id, "text": text})

    async def degrade(self, mechanism: str, detail: str, severity: str = "warn") -> None:
        """Record a capability DEGRADATION (a fallback fired) so the UI can warn the user
        that the system is not running at max capability. Persisted (tool='degradation')
        so it also shows when a finished task is re-opened."""
        with session_scope() as s:
            s.add(ToolInvocation(task_id=self.task_id, agent=self.current_agent, tool="degradation",
                                 args={"mechanism": mechanism},
                                 result_summary={"mechanism": mechanism, "detail": detail, "severity": severity},
                                 ok=(severity != "error")))
        await self.emit("degradation.notice",
                        {"mechanism": mechanism, "detail": detail, "severity": severity})

    # --- thread-safe variants (called from inside asyncio.to_thread worker) --- #
    def log_tool_sync(self, run_id: Optional[str], tool: str, args: dict,
                      summary: dict, ok: bool = True) -> None:
        with session_scope() as s:
            s.add(ToolInvocation(task_id=self.task_id, agent_run_id=run_id,
                                 agent=self.current_agent, tool=tool, args=args,
                                 result_summary=summary, ok=ok))
        emit_threadsafe(self.task_id, "tool.invoked", {
            "run_id": run_id, "agent": self.current_agent, "tool": tool,
            "args_brief": _brief(args)})
        emit_threadsafe(self.task_id, "tool.result", {
            "run_id": run_id, "tool": tool, "ok": ok, "summary": summary})

    def emit_reasoning_sync(self, run_id: Optional[str], reasoning: Optional[str] = None,
                            output: Optional[str] = None, kind: str = "think") -> None:
        if reasoning:
            emit_threadsafe(self.task_id, "agent.reasoning", {
                "run_id": run_id, "agent": self.current_agent, "kind": kind,
                "text": reasoning[:6000]})
        if output:
            emit_threadsafe(self.task_id, "agent.llm_output", {
                "run_id": run_id, "agent": self.current_agent, "text": output[:4000]})
        if reasoning or output:
            with session_scope() as s:
                s.add(ToolInvocation(task_id=self.task_id, agent_run_id=run_id,
                                     agent=self.current_agent, tool="llm_call",
                                     args={"kind": kind},
                                     result_summary={"reasoning": (reasoning or "")[:1200],
                                                     "output": (output or "")[:600]}))

    async def emit_reasoning(self, run_id: Optional[str], reasoning: Optional[str] = None,
                             output: Optional[str] = None, kind: str = "think") -> None:
        self.emit_reasoning_sync(run_id, reasoning, output, kind)


def _brief(args: dict) -> dict:
    out = {}
    for k, v in (args or {}).items():
        sv = str(v)
        out[k] = sv[:80] + ("…" if len(sv) > 80 else "")
    return out
