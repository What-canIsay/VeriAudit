"""Offline end-to-end smoke test: run the full pipeline on the bundled sample."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import init_db, session_scope  # noqa: E402
from app.models import AuditTask, Finding, Project, EvidenceChain  # noqa: E402
from app import orchestrator, workspace  # noqa: E402

SAMPLE = str((Path(__file__).resolve().parents[2] / "samples" / "vulnerable-python"))


def main():
    init_db()
    with session_scope() as s:
        p = Project(name="sample-vuln", source_type="local_path", source_ref=SAMPLE)
        s.add(p)
        s.flush()
        path = workspace.prepare_local(p.id, SAMPLE)
        p.workspace_path = str(path)
        pid = p.id
    import os as _os
    depth = _os.environ.get("SMOKE_DEPTH", "standard")
    with session_scope() as s:
        t = AuditTask(project_id=pid, depth=depth, status="queued", phase="queued")
        s.add(t)
        s.flush()
        tid = t.id

    asyncio.run(orchestrator.run_audit(tid))

    with session_scope() as s:
        t = s.get(AuditTask, tid)
        print(f"\n=== task status: {t.status}  counts: {t.counts}")
        fs = s.query(Finding).filter(Finding.task_id == tid).all()
        print(f"=== {len(fs)} findings ===")
        for f in fs:
            ev = s.query(EvidenceChain).filter(EvidenceChain.finding_id == f.id).first()
            sink = (ev.sink if ev else {}) or {}
            print(f"  [{f.confidence:18}] {(f.severity or {}).get('level','?'):8} "
                  f"{f.vuln_type:30} @ {sink.get('file')}:{sink.get('line')}")
    assert t.status == "succeeded", "pipeline did not succeed"
    assert len(fs) > 0, "no findings produced"
    print("\nSMOKE OK")


if __name__ == "__main__":
    main()
