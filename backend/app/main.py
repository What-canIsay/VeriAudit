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
    from . import orchestrator
    init_db()
    orchestrator.set_loop(asyncio.get_event_loop())


@app.get("/healthz")
def healthz():
    return {"ok": True, "mock_mode": settings.mock_mode}


# Optionally serve a built frontend (production single-serve). In dev the Vite
# server proxies to this API instead.
_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if _DIST.exists():
    app.mount("/", StaticFiles(directory=str(_DIST), html=True), name="frontend")
