"""Validator (验证官): 独立复核 + 双层验证 + 证据链固化 + 置信度分级。

第0层 可达性闸门 → 第1层 静态数据流验证(独立上下文) → 第2层 动态沙箱PoC(可选)。
"""
from __future__ import annotations

import asyncio
import hashlib

from .. import analysis, sandbox
from ..db import session_scope
from ..knowledge import SEVERITY_ORDER, rule_by_id
from ..llm.gateway import llm
from ..models import Artifact, EvidenceChain, Finding
from ..severity import score_from_vector
from . import prompts
from .context import AuditContext


def _priority(c):
    return (-SEVERITY_ORDER.get(c.get("_severity", "medium"), 0), -c.get("self_confidence", 0))


async def run(ctx: AuditContext) -> dict:
    run_id = await ctx.start_agent("validator", "verify")
    plan = ctx.state.get("plan", {})
    budget = plan.get("budget", {})
    max_verify = budget.get("max_verify", 20)
    do_dynamic = budget.get("dynamic_verification", False)

    cands = sorted(ctx.state.get("candidates", []), key=_priority)
    confirmed = suspected = rejected = dyn = 0
    seen_keys = set()

    for c in cands[:max_verify]:
        # 第0层：可达性闸门
        if c.get("reachable") is False:
            rejected += 1
            ctx.state["rejected"].append({"vuln_type": c["vuln_type"], "location": c["location"],
                                          "reason": "不可达（无法从对外入口点触达 sink）"})
            continue

        # 第1层：静态数据流验证（独立复核）
        verdict = await _static_verify(ctx, c)
        if verdict["verdict"] == "rejected":
            rejected += 1
            ctx.state["rejected"].append({"vuln_type": c["vuln_type"], "location": c["location"],
                                          "reason": verdict.get("confidence_reason", "静态验证判定不成立")})
            await ctx.emit("finding.rejected", {"vuln_type": c["vuln_type"],
                                                "location": c["location"]})
            continue

        # 第2层：动态沙箱 PoC（按类型/预算触发）
        dynamic = None
        rule = rule_by_id(c.get("rule_id", ""))
        if do_dynamic and rule and rule.get("reproducible"):
            await ctx.think(run_id, f"尝试在隔离沙箱中复现 {c['vuln_type']} …")
            dynamic = await asyncio.to_thread(sandbox.try_reproduce, ctx.root, c)
            await ctx.emit("sandbox.poc_attempt", {
                "vuln_type": c["vuln_type"],
                "attempted": dynamic.get("attempted"),
                "reproduced": dynamic.get("reproduced")})

        # 置信度分级
        if dynamic and dynamic.get("reproduced"):
            confidence = "CONFIRMED_DYNAMIC"
            confirmed += 1
            dyn += 1
        elif verdict["verdict"] == "confirmed":
            confidence = "CONFIRMED_STATIC"
            confirmed += 1
        else:
            confidence = "SUSPECTED"
            suspected += 1

        finding = await _persist_finding(ctx, c, verdict, dynamic, confidence, seen_keys)
        if finding:
            await ctx.emit("finding.confirmed", {
                "finding_id": finding["id"], "vuln_type": c["vuln_type"],
                "confidence": confidence, "severity": finding["severity"],
                "title": finding["title"]})

    out = {"confirmed": confirmed, "suspected": suspected, "rejected": rejected,
           "dynamic_reproduced": dyn}
    await ctx.emit("verify.ready", out)
    await ctx.finish_agent(run_id, out)
    return out


async def _static_verify(ctx: AuditContext, c: dict) -> dict:
    """LLM-as-judge in cloud mode; heuristic in mock mode."""
    if llm.enabled:
        window = _code_window(ctx.root, c)
        taint_txt = _taint_text(c)
        user = (f"漏洞类型: {c['vuln_type']}\n位置: {c['location']['file']}:{c['location']['line']}\n"
                f"可达性: {c.get('reachability')}\n污点路径:\n{taint_txt}\n\n代码上下文:\n{window}\n\n"
                + prompts.VALIDATOR_JUDGE_INSTR)
        j = await asyncio.to_thread(llm.judge, "validator", prompts.VALIDATOR, user)
        if j and j.get("verdict") in ("confirmed", "suspected", "rejected"):
            return j
    # heuristic fallback
    reach = c.get("reachability", {})
    sanitized = bool(c.get("_sanitized"))
    has_source = bool(c.get("_source"))
    if sanitized and not has_source:
        return {"verdict": "rejected", "confidence_reason": "路径上存在有效净化且未见明确污点源。"}
    if has_source and reach.get("reachable"):
        return {"verdict": "confirmed",
                "confidence_reason": "不可信输入无有效净化地到达危险汇聚点，且可达。",
                "poc": rule_poc(c), "remediation": rule_remed(c)}
    return {"verdict": "suspected",
            "confidence_reason": "存在危险汇聚点但污点/可达性证据不完整，建议人工复核。",
            "poc": rule_poc(c), "remediation": rule_remed(c)}


async def _persist_finding(ctx, c, verdict, dynamic, confidence, seen_keys):
    rule = rule_by_id(c.get("rule_id", "")) or {}
    vector = rule.get("cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    sev = score_from_vector(vector)
    dedup = hashlib.md5(
        f"{c['vuln_type']}|{c['location']['file']}|{c['location']['line']}".encode()).hexdigest()[:16]
    if dedup in seen_keys:
        return None
    seen_keys.add(dedup)

    title = f"{rule.get('name', c['vuln_type'])} — {c['location']['file']}:{c['location']['line']}"
    remediation = verdict.get("remediation") or rule.get("remediation", "")
    poc = verdict.get("poc") or (dynamic or {}).get("poc_code") or rule.get("poc_hint", "")

    taint = c.get("taint", {})
    with session_scope() as s:
        f = Finding(task_id=ctx.task_id, vuln_type=c["vuln_type"], title=title,
                    confidence=confidence, severity=sev, cvss_vector=vector,
                    status="open", dedup_key=dedup, remediation=remediation)
        s.add(f)
        s.flush()
        ev = EvidenceChain(
            finding_id=f.id,
            entry_point=(c.get("reachability", {}).get("entry_points") or [None])[0],
            source=c.get("_source"),
            sink=c["location"],
            taint_path=taint.get("taint_path", []),
            sanitizers=taint.get("sanitizers", []),
            reachability=c.get("reachability", {}),
            static_verdict={"status": verdict["verdict"],
                            "rationale": verdict.get("confidence_reason", ""),
                            "by": "llm" if llm.enabled else "heuristic"},
            dynamic_verification=dynamic,
        )
        s.add(ev)
        if poc:
            s.add(Artifact(finding_id=f.id, kind="poc_code", content=str(poc),
                           meta={"reproducible": rule.get("reproducible", False)}))
        if dynamic and dynamic.get("sandbox_log"):
            s.add(Artifact(finding_id=f.id, kind="sandbox_log",
                           content=dynamic["sandbox_log"], meta={"reproduced": dynamic.get("reproduced")}))
            if dynamic.get("request"):
                s.add(Artifact(finding_id=f.id, kind="http_exchange",
                               content=str(dynamic.get("request")), meta={}))
        s.flush()
        fid = f.id
    return {"id": fid, "title": title, "severity": sev}


# --- helpers ---
def _code_window(root, c, ctx_lines: int = 18) -> str:
    try:
        f = root / c["location"]["file"]
        lines = analysis.read_text(f).splitlines()
        ln = c["location"]["line"]
        a = max(0, ln - ctx_lines)
        b = min(len(lines), ln + ctx_lines)
        return "\n".join(f"{i+1}: {lines[i]}" for i in range(a, b))[:4000]
    except Exception:
        return c["location"].get("snippet", "")


def _taint_text(c) -> str:
    hops = c.get("taint", {}).get("taint_path", [])
    return "\n".join(
        f"  - {h['location'].get('file')}:{h['location'].get('line')} [{h.get('variable')}] {h.get('transform')}"
        for h in hops)


def rule_poc(c) -> str:
    r = rule_by_id(c.get("rule_id", "")) or {}
    return r.get("poc_hint", "")


def rule_remed(c) -> str:
    r = rule_by_id(c.get("rule_id", "")) or {}
    return r.get("remediation", "")
