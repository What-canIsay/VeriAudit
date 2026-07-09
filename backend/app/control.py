"""Cooperative start / pause / cancel control for a running audit task.

The pipeline runs as ONE asyncio task whose long phases are agentic loops, most of them
executing in worker threads (blocking LLM/subprocess calls). We can't hard-kill a thread
mid-call, so control is COOPERATIVE: the orchestrator (between phases) and every agentic
loop (between model turns) call `checkpoint()`, which

  · blocks (in the calling thread) while the task is PAUSED, and
  · returns False once the task is CANCELLED,

so the caller stops at the next safe point. Uses threading primitives so it works
identically from the async orchestrator (via asyncio.to_thread) and from worker threads.
"""
from __future__ import annotations

import threading
from typing import Dict, Optional


class Control:
    def __init__(self) -> None:
        self._resume = threading.Event()
        self._resume.set()          # set = running (not paused)
        self._cancelled = False
        self.state = "running"      # running | paused | cancelled

    def pause(self) -> bool:
        if self._cancelled or self.state != "running":
            return False
        self._resume.clear()
        self.state = "paused"
        return True

    def resume(self) -> bool:
        if self._cancelled or self.state != "paused":
            return False
        self.state = "running"
        self._resume.set()
        return True

    def cancel(self) -> bool:
        if self._cancelled:
            return False
        self._cancelled = True
        self.state = "cancelled"
        self._resume.set()          # unblock anyone parked in checkpoint()
        return True

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def checkpoint(self) -> bool:
        """Block while paused; return False if cancelled (caller should stop). Call from a
        worker thread directly; from the event loop call via asyncio.to_thread so the loop
        isn't blocked while paused."""
        self._resume.wait()
        return not self._cancelled


_REG: Dict[str, Control] = {}


def create(task_id: str) -> Control:
    c = Control()
    _REG[task_id] = c
    return c


def get(task_id: str) -> Optional[Control]:
    return _REG.get(task_id)


def get_or_create(task_id: str) -> Control:
    return _REG.get(task_id) or create(task_id)


def remove(task_id: str) -> None:
    _REG.pop(task_id, None)
