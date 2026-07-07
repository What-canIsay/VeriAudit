"""ORM models — mirrors docs/05-data-model-and-api.md (SQLite-friendly)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Project(Base):
    __tablename__ = "project"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    source_type: Mapped[str] = mapped_column(String(20))          # git_url | zip_upload | local_path
    source_ref: Mapped[str] = mapped_column(Text)
    commit_sha: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    languages: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="ready")
    workspace_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    tasks: Mapped[list["AuditTask"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class AuditTask(Base):
    __tablename__ = "audit_task"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    depth: Mapped[str] = mapped_column(String(20), default="standard")   # fast | standard | deep
    status: Mapped[str] = mapped_column(String(20), default="queued")
    phase: Mapped[str] = mapped_column(String(20), default="queued")
    round: Mapped[int] = mapped_column(Integer, default=0)
    budget: Mapped[dict] = mapped_column(JSON, default=dict)
    counts: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    project: Mapped["Project"] = relationship(back_populates="tasks")


class Candidate(Base):
    __tablename__ = "candidate"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("audit_task.id"))
    vuln_type: Mapped[str] = mapped_column(String(80))
    location: Mapped[dict] = mapped_column(JSON, default=dict)
    self_confidence: Mapped[float] = mapped_column(Float, default=0.5)
    rationale: Mapped[str] = mapped_column(Text, default="")
    origin: Mapped[str] = mapped_column(String(20), default="llm")   # sast | llm | kb | sca
    # tracer enrichment
    taint_path: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    reachability: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    reachable: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Finding(Base):
    __tablename__ = "finding"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("audit_task.id"))
    vuln_type: Mapped[str] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(300))
    confidence: Mapped[str] = mapped_column(String(30))     # CONFIRMED_DYNAMIC | CONFIRMED_STATIC | SUSPECTED | REJECTED
    severity: Mapped[dict] = mapped_column(JSON, default=dict)   # {level, score}
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="open")
    dedup_key: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    evidence: Mapped[Optional["EvidenceChain"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", uselist=False
    )
    artifacts: Mapped[list["Artifact"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class EvidenceChain(Base):
    __tablename__ = "evidence_chain"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("finding.id"))
    entry_point: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    source: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    sink: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    taint_path: Mapped[list] = mapped_column(JSON, default=list)
    sanitizers: Mapped[list] = mapped_column(JSON, default=list)
    reachability: Mapped[dict] = mapped_column(JSON, default=dict)
    static_verdict: Mapped[dict] = mapped_column(JSON, default=dict)
    dynamic_verification: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    finding: Mapped["Finding"] = relationship(back_populates="evidence")


class Artifact(Base):
    __tablename__ = "artifact"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("finding.id"))
    kind: Mapped[str] = mapped_column(String(30))   # poc_code | http_exchange | sandbox_log | canary_hit
    content: Mapped[str] = mapped_column(Text, default="")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    finding: Mapped["Finding"] = relationship(back_populates="artifacts")


class AgentRun(Base):
    __tablename__ = "agent_run"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("audit_task.id"))
    agent: Mapped[str] = mapped_column(String(30))
    node: Mapped[str] = mapped_column(String(30))
    parent_run_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="running")
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    tokens: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class ToolInvocation(Base):
    __tablename__ = "tool_invocation"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("audit_task.id"))
    agent_run_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    agent: Mapped[str] = mapped_column(String(30), default="")
    tool: Mapped[str] = mapped_column(String(40))
    args: Mapped[dict] = mapped_column(JSON, default=dict)
    result_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    cost_hint: Mapped[dict] = mapped_column(JSON, default=dict)
    ts: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Report(Base):
    __tablename__ = "report"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("audit_task.id"))
    format: Mapped[str] = mapped_column(String(20))
    content: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
