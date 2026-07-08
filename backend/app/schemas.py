"""Pydantic request/response schemas and ORM serializers."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class ProjectCreate(BaseModel):
    name: str
    source_type: str = "git_url"          # git_url | local_path
    source_ref: str                       # url or local path


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    source_type: Optional[str] = None     # git_url | local_path
    source_ref: Optional[str] = None


class TaskCreate(BaseModel):
    depth: str = "standard"               # fast | standard | deep
    languages: Optional[List[str]] = None
    config: Dict[str, Any] = {}


def project_out(p) -> dict:
    return {
        "id": p.id, "name": p.name, "source_type": p.source_type,
        "source_ref": p.source_ref, "commit_sha": p.commit_sha,
        "languages": p.languages or {}, "status": p.status,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


def task_out(t) -> dict:
    return {
        "id": t.id, "project_id": t.project_id, "depth": t.depth,
        "status": t.status, "phase": t.phase, "round": t.round,
        "budget": t.budget or {}, "counts": t.counts or {}, "error": t.error,
        "started_at": t.started_at.isoformat() if t.started_at else None,
        "finished_at": t.finished_at.isoformat() if t.finished_at else None,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


def evidence_out(e) -> Optional[dict]:
    if e is None:
        return None
    return {
        "entry_point": e.entry_point, "source": e.source, "sink": e.sink,
        "taint_path": e.taint_path or [], "sanitizers": e.sanitizers or [],
        "reachability": e.reachability or {}, "static_verdict": e.static_verdict or {},
        "dynamic_verification": e.dynamic_verification,
    }


def finding_out(f, full: bool = False) -> dict:
    d = {
        "id": f.id, "task_id": f.task_id, "vuln_type": f.vuln_type,
        "title": f.title, "confidence": f.confidence, "severity": f.severity or {},
        "cvss_vector": f.cvss_vector, "status": f.status,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }
    if full:
        d["remediation"] = f.remediation
        d["evidence"] = evidence_out(f.evidence)
        d["artifacts"] = [
            {"id": a.id, "kind": a.kind, "meta": a.meta or {}, "content": a.content}
            for a in f.artifacts
        ]
    return d
