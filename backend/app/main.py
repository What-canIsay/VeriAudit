"""VeriAudit API entrypoint."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .api.routes import router
from .config import settings
from .db import init_db

app = FastAPI(title="VeriAudit", version="0.1.0",
              description="多智能体代码安全审计与验证系统")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.on_event("startup")
async def _startup() -> None:
    import asyncio
    from datetime import datetime, timezone
    from . import events, orchestrator
    from .db import session_scope
    from .models import AuditTask
    init_db()
    loop = asyncio.get_event_loop()
    orchestrator.set_loop(loop)
    events.set_loop(loop)
    # reconcile ORPHANED tasks: the in-process orchestrator that ran them died with the
    # previous server, so anything still 'running/queued/paused/cancelling' can never finish
    # → mark failed so the UI doesn't show zombie "running" tasks forever.
    _ACTIVE = ("running", "queued", "paused", "cancelling")
    with session_scope() as s:
        for t in s.query(AuditTask).filter(AuditTask.status.in_(_ACTIVE)).all():
            t.status = "failed"
            t.error = "中断：后端已重启（该任务的执行进程随上次运行结束而丢失）"
            t.finished_at = datetime.now(timezone.utc)


@app.get("/healthz")
def healthz():
    return {"ok": True, "mock_mode": settings.mock_mode}


# Optionally serve a built frontend (production single-serve). In dev the Vite
# server proxies to this API instead.
_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if _DIST.exists():
    app.mount("/", StaticFiles(directory=str(_DIST), html=True), name="frontend")
