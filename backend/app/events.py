"""In-process event bus for real-time task events (SSE).

Single-process MVP: the orchestrator runs as an asyncio background task in the
same process as the API, so an in-memory pub/sub is sufficient. Events are also
persisted (agent_run / tool_invocation) so /timeline can replay history.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, List

# task_id -> list of subscriber queues
_subscribers: Dict[str, List["asyncio.Queue[dict]"]] = {}
# task_id -> retained recent events (for late subscribers within one process)
_history: Dict[str, List[dict]] = {}
_MAX_HISTORY = 2000


def subscribe(task_id: str) -> "asyncio.Queue[dict]":
    q: "asyncio.Queue[dict]" = asyncio.Queue()
    _subscribers.setdefault(task_id, []).append(q)
    return q


def unsubscribe(task_id: str, q: "asyncio.Queue[dict]") -> None:
    lst = _subscribers.get(task_id)
    if lst and q in lst:
        lst.remove(q)


def history(task_id: str) -> List[dict]:
    return list(_history.get(task_id, []))


async def emit(task_id: str, event: str, data: dict) -> None:
    payload = {
        "event": event,
        "data": data,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    hist = _history.setdefault(task_id, [])
    hist.append(payload)
    if len(hist) > _MAX_HISTORY:
        del hist[: len(hist) - _MAX_HISTORY]
    for q in list(_subscribers.get(task_id, [])):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:  # pragma: no cover
            pass


def sse_format(payload: dict) -> str:
    return f"event: {payload['event']}\ndata: {json.dumps(payload['data'], ensure_ascii=False)}\n\n"
