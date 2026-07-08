"""Reporter (报告官): 汇总统计 + 执行摘要，并生成默认报告。"""
from __future__ import annotations

import asyncio

from ..db import session_scope
from ..llm.gateway import llm
from ..models import AuditTask, Finding
from .. import report as report_mod
from . import prompts
from .context import AuditContext


async def run(ctx: AuditContext) -> dict:
    run_id = await ctx.start_agent("reporter", "report")

    with session_scope() as s:
        findings = s.query(Finding).filter(Finding.task_id == ctx.task_id).all()
        counts = _counts(findings)
        counts["rejected"] = len(ctx.state.get("rejected", []))

    summary = _template_summary(counts)
    if llm.enabled:
        j = await asyncio.to_thread(
            llm.judge, "reporter", prompts.REPORTER,
            f"统计：{counts}。以 JSON 返回 {{\"summary\": \"3-6句执行摘要\"}}。")
        if j and j.get("summary"):
            summary = j["summary"]

    # 生成并落库默认报告（markdown + json + sarif 均可按需再生成）
    await asyncio.to_thread(report_mod.generate_and_store, ctx.task_id, "markdown",
                            summary, ctx.state.get("rejected", []))

    with session_scope() as s:
        t = s.get(AuditTask, ctx.task_id)
        if t:
            t.counts = counts

    await ctx.emit("report.ready", {"counts": counts, "summary": summary})
    await ctx.finish_agent(run_id, {"counts": counts})
    return {"counts": counts, "summary": summary}


def _counts(findings) -> dict:
    out = {"confirmed_dynamic": 0, "confirmed_static": 0, "suspected": 0,
           "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}
    for f in findings:
        if f.confidence == "REJECTED":
            continue
        if f.confidence == "CONFIRMED_DYNAMIC":
            out["confirmed_dynamic"] += 1
        elif f.confidence == "CONFIRMED_STATIC":
            out["confirmed_static"] += 1
        elif f.confidence == "SUSPECTED":
            out["suspected"] += 1
        lvl = (f.severity or {}).get("level", "info")
        out["by_severity"][lvl] = out["by_severity"].get(lvl, 0) + 1
    out["total_findings"] = out["confirmed_dynamic"] + out["confirmed_static"] + out["suspected"]
    return out


def _template_summary(counts: dict) -> str:
    total = counts.get("total_findings", 0)
    crit = counts["by_severity"].get("critical", 0)
    high = counts["by_severity"].get("high", 0)
    dyn = counts.get("confirmed_dynamic", 0)
    return (f"本次审计共确认 {total} 项漏洞，其中严重 {crit} 项、高危 {high} 项，"
            f"{dyn} 项已在隔离沙箱中动态复现（最高置信度）。"
            f"另有 {counts.get('suspected', 0)} 项疑似需人工复核，{counts.get('rejected', 0)} 项经验证排除。"
            f"建议优先修复严重/高危且已复现的漏洞。")
