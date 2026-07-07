"""REST + SSE endpoints (docs/05)."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import desc
from sqlalchemy.orm import Session

from .. import events, orchestrator, report as report_mod, workspace
from ..analysis import detect_stack
from ..config import settings
from ..db import get_db
from ..models import (AgentRun, AuditTask, Candidate, EvidenceChain, Finding,
                      Project, ToolInvocation)
from ..schemas import ProjectCreate, TaskCreate, finding_out, project_out, task_out
from ..sandbox import docker_available

router = APIRouter(prefix="/api/v1")


@router.get("/config")
def get_config():
    from ..config import BASE_DIR
    sample = BASE_DIR.parent / "samples" / "vulnerable-python"
    return {
        "mock_mode": settings.mock_mode,
        "llm_provider": settings.llm_provider,
        "model_tiers": {"strong": settings.model_strong, "mid": settings.model_mid,
                        "cheap": settings.model_cheap},
        "sandbox_available": docker_available(),
        "semgrep_enabled": settings.enable_semgrep,
        "sample_path": str(sample) if sample.exists() else None,
    }


# --------------------------- projects --------------------------- #
@router.post("/projects")
def create_project(body: ProjectCreate, db: Session = Depends(get_db)):
    p = Project(name=body.name, source_type=body.source_type, source_ref=body.source_ref)
    db.add(p)
    db.flush()
    try:
        from pathlib import Path
        if body.source_type == "git_url":
            path = workspace.prepare_git(p.id, body.source_ref)
        elif body.source_type == "local_path":
            path = workspace.prepare_local(p.id, body.source_ref)
        else:
            raise HTTPException(400, f"unsupported source_type {body.source_type}")
        p.workspace_path = str(path)
        p.commit_sha = workspace.head_commit(path)
        stack = detect_stack(path)
        p.languages = stack["languages"]
        p.status = "ready"
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(400, f"prepare workspace failed: {e}")
    db.commit()
    db.refresh(p)
    return project_out(p)


@router.get("/projects")
def list_projects(db: Session = Depends(get_db)):
    rows = db.query(Project).order_by(desc(Project.created_at)).all()
    return [project_out(p) for p in rows]


@router.get("/projects/{pid}")
def get_project(pid: str, db: Session = Depends(get_db)):
    p = db.get(Project, pid)
    if not p:
        raise HTTPException(404, "project not found")
    tasks = db.query(AuditTask).filter(AuditTask.project_id == pid).order_by(desc(AuditTask.created_at)).all()
    return {**project_out(p), "tasks": [task_out(t) for t in tasks]}


# --------------------------- tasks --------------------------- #
@router.post("/projects/{pid}/tasks")
async def create_task(pid: str, body: TaskCreate, db: Session = Depends(get_db)):
    p = db.get(Project, pid)
    if not p:
        raise HTTPException(404, "project not found")
    if not p.workspace_path:
        raise HTTPException(400, "project workspace not ready")
    t = AuditTask(project_id=pid, depth=body.depth, config=body.config or {},
                  status="queued", phase="queued")
    db.add(t)
    db.commit()
    db.refresh(t)
    orchestrator.launch(t.id)  # background asyncio task
    return task_out(t)


@router.get("/tasks/{tid}")
def get_task(tid: str, db: Session = Depends(get_db)):
    t = db.get(AuditTask, tid)
    if not t:
        raise HTTPException(404, "task not found")
    return task_out(t)


@router.get("/tasks/{tid}/timeline")
def get_timeline(tid: str, db: Session = Depends(get_db)):
    runs = db.query(AgentRun).filter(AgentRun.task_id == tid).order_by(AgentRun.started_at).all()
    tools = db.query(ToolInvocation).filter(ToolInvocation.task_id == tid).order_by(ToolInvocation.ts).all()
    items = []
    for r in runs:
        items.append({"kind": "agent", "ts": r.started_at.isoformat() if r.started_at else None,
                      "agent": r.agent, "node": r.node, "status": r.status,
                      "run_id": r.id, "output": r.output})
    for tv in tools:
        items.append({"kind": "tool", "ts": tv.ts.isoformat() if tv.ts else None,
                      "agent": tv.agent, "tool": tv.tool, "ok": tv.ok,
                      "summary": tv.result_summary, "run_id": tv.agent_run_id})
    items.sort(key=lambda x: x["ts"] or "")
    return items


@router.get("/tasks/{tid}/findings")
def list_findings(tid: str, confidence: str = Query(None), db: Session = Depends(get_db)):
    q = db.query(Finding).filter(Finding.task_id == tid)
    if confidence:
        q = q.filter(Finding.confidence == confidence)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = q.all()
    rows.sort(key=lambda f: order.get((f.severity or {}).get("level", "info"), 9))
    return [finding_out(f) for f in rows]


@router.get("/findings/{fid}")
def get_finding(fid: str, db: Session = Depends(get_db)):
    f = db.get(Finding, fid)
    if not f:
        raise HTTPException(404, "finding not found")
    return finding_out(f, full=True)


@router.post("/tasks/{tid}/report")
def gen_report(tid: str, format: str = Query("markdown"), db: Session = Depends(get_db)):
    t = db.get(AuditTask, tid)
    if not t:
        raise HTTPException(404, "task not found")
    if format not in ("markdown", "json", "sarif"):
        raise HTTPException(400, "format must be markdown|json|sarif")
    content = report_mod.render(tid, format)
    return {"format": format, "content": content}


# --------------------------- SSE --------------------------- #
@router.get("/tasks/{tid}/events")
async def sse(tid: str):
    async def gen():
        q = events.subscribe(tid)
        try:
            for payload in events.history(tid):
                yield events.sse_format(payload)
            while True:
                try:
                    payload = await asyncio.wait_for(q.get(), timeout=15)
                    yield events.sse_format(payload)
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            events.unsubscribe(tid, q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
