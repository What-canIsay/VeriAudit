"""Structured report rendering: Markdown / JSON / SARIF (docs/06)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Optional

from .db import session_scope
from .models import AuditTask, EvidenceChain, Finding, Project, Report

_CONF_LABEL = {
    "CONFIRMED_DYNAMIC": "已动态复现", "CONFIRMED_STATIC": "数据流已确证",
    "SUSPECTED": "疑似(需人工复核)", "REJECTED": "已排除",
}
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def _load(task_id: str):
    with session_scope() as s:
        task = s.get(AuditTask, task_id)
        project = s.get(Project, task.project_id) if task else None
        findings = s.query(Finding).filter(Finding.task_id == task_id).all()
        data = []
        for f in findings:
            ev = s.query(EvidenceChain).filter(EvidenceChain.finding_id == f.id).first()
            arts = [{"kind": a.kind, "content": a.content, "meta": a.meta} for a in f.artifacts]
            data.append({
                "id": f.id, "vuln_type": f.vuln_type, "title": f.title,
                "confidence": f.confidence, "severity": f.severity or {},
                "cvss_vector": f.cvss_vector, "remediation": f.remediation,
                "evidence": _ev_dict(ev), "artifacts": arts,
            })
        proj = {"name": project.name if project else "?",
                "source": project.source_ref if project else "",
                "commit": project.commit_sha if project else None,
                "languages": (project.languages if project else {}) or {}}
        counts = task.counts if task else {}
        depth = task.depth if task else "standard"
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    corder = {"CONFIRMED_DYNAMIC": 0, "CONFIRMED_STATIC": 1, "SUSPECTED": 2, "REJECTED": 3}
    data.sort(key=lambda d: (order.get(d["severity"].get("level", "info"), 9),
                             corder.get(d["confidence"], 9)))
    return proj, counts, depth, data


def _ev_dict(ev: Optional[EvidenceChain]):
    if not ev:
        return None
    return {"entry_point": ev.entry_point, "source": ev.source, "sink": ev.sink,
            "taint_path": ev.taint_path or [], "sanitizers": ev.sanitizers or [],
            "reachability": ev.reachability or {}, "static_verdict": ev.static_verdict or {},
            "dynamic_verification": ev.dynamic_verification}


def render(task_id: str, fmt: str, summary: str = "", rejected: Optional[List[dict]] = None) -> str:
    proj, counts, depth, findings = _load(task_id)
    rejected = rejected or []
    if fmt == "json":
        return json.dumps({"project": proj, "depth": depth, "summary": summary,
                           "counts": counts, "findings": findings, "rejected": rejected},
                          ensure_ascii=False, indent=2)
    if fmt == "sarif":
        return _sarif(findings)
    return _markdown(proj, counts, depth, summary, findings, rejected)


def _markdown(proj, counts, depth, summary, findings, rejected) -> str:
    L = []
    L.append(f"# VeriAudit 安全审计报告 — {proj['name']}\n")
    L.append(f"> 生成时间：{datetime.now(timezone.utc).isoformat()} · 深度档位：`{depth}`\n")
    L.append("## 1. 概要\n")
    L.append(f"- **项目来源**：{proj['source']}")
    if proj.get("commit"):
        L.append(f"- **Commit**：`{proj['commit']}`")
    L.append(f"- **语言分布**：{proj['languages']}")
    bys = counts.get("by_severity", {})
    L.append(f"- **结果总览**：确认 {counts.get('total_findings', 0)} 项 "
             f"(严重 {bys.get('critical',0)} / 高 {bys.get('high',0)} / 中 {bys.get('medium',0)} / 低 {bys.get('low',0)})，"
             f"其中动态复现 {counts.get('confirmed_dynamic',0)} 项，疑似 {counts.get('suspected',0)} 项，已排除 {len(rejected)} 项")
    if summary:
        L.append(f"\n**结论**：{summary}\n")

    L.append("\n## 2. 漏洞列表\n")
    if not findings:
        L.append("_未发现确认漏洞。_\n")
    for i, f in enumerate(findings, 1):
        sev = f["severity"]
        L.append(f"### 2.{i} {f['title']}\n")
        L.append(f"- **类型**：{f['vuln_type']}")
        L.append(f"- **严重度**：{sev.get('level','?').upper()} (CVSS {sev.get('score','?')} `{f['cvss_vector']}`)")
        L.append(f"- **置信度**：{_CONF_LABEL.get(f['confidence'], f['confidence'])}")
        ev = f.get("evidence") or {}
        sink = ev.get("sink") or {}
        L.append(f"\n**① 位置** — sink：`{sink.get('file')}:{sink.get('line')}`"
                 + (f" (函数 `{sink.get('function')}`)" if sink.get("function") else ""))
        src = ev.get("source")
        if src:
            L.append(f"  · source：`{src.get('file')}:{src.get('line')}`")
        L.append("\n**② 调用/污点路径**：")
        for h in ev.get("taint_path", []):
            loc = h.get("location", {})
            L.append(f"  - `{loc.get('file')}:{loc.get('line')}` [{h.get('variable')}] {h.get('transform')}")
        reach = ev.get("reachability", {})
        L.append(f"\n**③ 可达性**：{'可达' if reach.get('reachable') else '待确认'} "
                 f"(置信 {reach.get('confidence')}) — {reach.get('note','')}")
        sv = ev.get("static_verdict", {})
        L.append(f"\n**④ 验证**：静态判定 `{sv.get('status')}` — {sv.get('rationale','')}")
        dyn = ev.get("dynamic_verification")
        if dyn and dyn.get("attempted"):
            L.append(f"  · 动态：{'✅ 已复现' if dyn.get('reproduced') else '未复现'} — {dyn.get('observation') or dyn.get('reason','')}")
        for a in f.get("artifacts", []):
            if a["kind"] == "poc_code":
                L.append(f"\n**PoC**：\n```\n{a['content']}\n```")
        if f.get("remediation"):
            L.append(f"\n**修复建议**：{f['remediation']}\n")

    if rejected:
        L.append("\n## 3. 已排除项（附录）\n")
        for r in rejected:
            loc = r.get("location", {})
            L.append(f"- {r.get('vuln_type')} @ `{loc.get('file')}:{loc.get('line')}` — {r.get('reason')}")

    L.append("\n## 4. 方法与局限\n")
    L.append("- 采用「高召回发现 + 可达性闸门 + 独立双层验证」流水线；置信度分级如实标注。")
    L.append("- 动态验证针对可复现类漏洞在隔离沙箱中进行；逻辑类漏洞以静态数据流结论为准。")
    return "\n".join(L)


def _sarif(findings) -> str:
    rules, results = [], []
    seen_rules = set()
    for f in findings:
        rid = f["vuln_type"]
        if rid not in seen_rules:
            seen_rules.add(rid)
            rules.append({"id": rid, "name": rid,
                          "shortDescription": {"text": f["vuln_type"]}})
        ev = f.get("evidence") or {}
        sink = ev.get("sink") or {}
        level = _SARIF_LEVEL.get(f["severity"].get("level", "info"), "warning")
        thread_locs = []
        for h in ev.get("taint_path", []):
            loc = h.get("location", {})
            thread_locs.append({"location": {"physicalLocation": {
                "artifactLocation": {"uri": loc.get("file", "")},
                "region": {"startLine": int(loc.get("line", 1) or 1)}},
                "message": {"text": f"{h.get('variable')} {h.get('transform')}"}}})
        results.append({
            "ruleId": rid, "level": level,
            "message": {"text": f"{f['title']} [{f['confidence']}]"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": sink.get("file", "")},
                "region": {"startLine": int(sink.get("line", 1) or 1)}}}],
            "codeFlows": ([{"threadFlows": [{"locations": thread_locs}]}] if thread_locs else []),
            "properties": {"cvss": f["cvss_vector"], "confidence": f["confidence"]},
        })
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "VeriAudit", "version": "0.1.0",
                                          "informationUri": "https://veriaudit.local",
                                          "rules": rules}}, "results": results}]}
    return json.dumps(doc, ensure_ascii=False, indent=2)


def generate_and_store(task_id: str, fmt: str, summary: str = "",
                       rejected: Optional[List[dict]] = None) -> str:
    content = render(task_id, fmt, summary, rejected)
    with session_scope() as s:
        prev = s.query(Report).filter(Report.task_id == task_id, Report.format == fmt).count()
        s.add(Report(task_id=task_id, format=fmt, content=content,
                     summary={"text": summary}, version=prev + 1))
    return content
