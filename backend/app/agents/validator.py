"""Validator (验证官): independent double-tier verification + confidence grading.

第0层 可达性闸门 → 第1层 静态数据流验证(独立复核) → 第2层 动态沙箱PoC(模型决定是否值得)。

降漏报要点：
- 疑似净化但无法排除 → 判 SUSPECTED（供人工复核），不再直接 REJECTED（避免误杀=漏报）。
- 专业扫描器(SAST/密钥/依赖)来源的候选默认较高信任。
成本要点：
- 仅对 top-N（llm_triage_limit）候选用 LLM 判定；确定性工具findings(密钥/依赖)不耗费 LLM。
"""
from __future__ import annotations

import asyncio
import hashlib

from .. import analysis, sandbox
from ..config import settings
from ..db import session_scope
from ..knowledge import SEVERITY_ORDER, rule_by_id
from ..llm.gateway import llm
from ..models import Artifact, EvidenceChain, Finding
from ..severity import score_from_vector
from . import prompts
from .context import AuditContext

_TRUSTED_ORIGINS = {"semgrep", "codeql", "gitleaks", "osv"}
_DETERMINISTIC_RULES = {"hardcoded-secret", "vulnerable-dependency"}


def _priority(c):
    return (-SEVERITY_ORDER.get(c.get("_severity", "medium"), 0), -c.get("self_confidence", 0))


async def run(ctx: AuditContext) -> dict:
    run_id = await ctx.start_agent("validator", "verify")
    budget = ctx.state.get("plan", {}).get("budget", {}) or ctx.state.get("budget", {})
    max_verify = budget.get("max_verify", settings.max_verify)
    do_dynamic = budget.get("dynamic_verification", False)
    llm_left = budget.get("llm_triage_limit", settings.llm_triage_limit)

    cands = sorted(ctx.state.get("candidates", []), key=_priority)
    confirmed = suspected = rejected = dyn = 0
    seen_keys = set()

    for c in cands[:max_verify]:
        if c.get("reachable") is False:
            rejected += 1
            await _persist_rejected(ctx, c, "不可达（无法从对外入口点触达 sink）", seen_keys)
            await ctx.emit("finding.rejected", {"vuln_type": c["vuln_type"], "location": c["location"]})
            continue

        # decide whether to spend an LLM judge on this candidate (economy)
        deterministic = c.get("rule_id") in _DETERMINISTIC_RULES or c.get("origin") in ("gitleaks", "osv")
        use_llm = llm.enabled and not deterministic and llm_left > 0
        if use_llm:
            llm_left -= 1
        verdict = await _static_verify(ctx, run_id, c, use_llm)

        if verdict["verdict"] == "rejected":
            rejected += 1
            await _persist_rejected(ctx, c, verdict.get("confidence_reason", "静态验证判定不成立"), seen_keys)
            await ctx.emit("finding.rejected", {"vuln_type": c["vuln_type"], "location": c["location"]})
            continue

        dynamic = None
        rule = rule_by_id(c.get("rule_id", ""))
        want_dyn = verdict.get("want_dynamic", True)
        if do_dynamic and want_dyn and rule and rule.get("reproducible"):
            env = ctx.state.get("env")
            if env and env.get("ready"):
                await ctx.think(run_id, f"向常驻应用环境发起 PoC 复现 {c['vuln_type']} …")
                dynamic = await asyncio.to_thread(sandbox.reproduce_via_env, ctx.root, c, env)
            if dynamic is None:   # no standing env, or env-probe not applicable → ephemeral boot
                await ctx.think(run_id, f"在隔离沙箱中尝试复现 {c['vuln_type']} …")
                dynamic = await asyncio.to_thread(sandbox.try_reproduce, ctx.root, c)
            await ctx.emit("sandbox.poc_attempt", {"vuln_type": c["vuln_type"],
                                                   "attempted": dynamic.get("attempted"),
                                                   "reproduced": dynamic.get("reproduced")})

        if dynamic and dynamic.get("reproduced"):
            confidence = "CONFIRMED_DYNAMIC"; confirmed += 1; dyn += 1
        elif verdict["verdict"] == "confirmed":
            confidence = "CONFIRMED_STATIC"; confirmed += 1
        else:
            confidence = "SUSPECTED"; suspected += 1

        finding = await _persist_finding(ctx, c, verdict, dynamic, confidence, seen_keys)
        if finding:
            await ctx.emit("finding.confirmed", {"finding_id": finding["id"], "vuln_type": c["vuln_type"],
                                                 "confidence": confidence, "severity": finding["severity"],
                                                 "title": finding["title"]})

    out = {"confirmed": confirmed, "suspected": suspected, "rejected": rejected, "dynamic_reproduced": dyn}
    await ctx.emit("verify.ready", out)
    await ctx.finish_agent(run_id, out)
    return out


async def _static_verify(ctx: AuditContext, run_id, c: dict, use_llm: bool) -> dict:
    # deterministic tool findings (secrets / dependency CVEs) are trusted as-is
    if c.get("rule_id") in _DETERMINISTIC_RULES or c.get("origin") in ("gitleaks", "osv"):
        return {"verdict": "confirmed", "want_dynamic": False,
                "confidence_reason": "专业工具确定性检出（密钥/已知CVE依赖）。",
                "poc": rule_poc(c), "remediation": rule_remed(c)}

    if use_llm:
        window = _code_window(ctx.root, c)
        user = (f"漏洞类型: {c['vuln_type']}\n位置: {c['location']['file']}:{c['location']['line']}\n"
                f"来源: {c.get('origin')}\n可达性: {c.get('reachability')}\n污点路径:\n{_taint_text(c)}\n\n"
                f"代码上下文:\n{window}\n\n" + prompts.VALIDATOR_JUDGE_INSTR)
        b = ctx.state.get("budget", {})
        j, reasoning, content = await asyncio.to_thread(
            llm.judge_ex, "validator", prompts.VALIDATOR, user,
            b.get("llm_timeout_sec"), b.get("llm_num_retries"))
        await ctx.emit_reasoning(run_id, reasoning=reasoning,
                                 output=content if content else None, kind="verify")
        if j and j.get("verdict") in ("confirmed", "suspected", "rejected"):
            return j

    # heuristic fallback
    if c.get("origin") in _TRUSTED_ORIGINS:   # curated SAST → trust unless proven otherwise
        return {"verdict": "confirmed", "want_dynamic": True,
                "confidence_reason": "专业 SAST 工具命中且未见有效净化。",
                "poc": rule_poc(c), "remediation": rule_remed(c)}
    reach = c.get("reachability", {})
    sanitized = bool(c.get("_sanitized"))
    has_source = bool(c.get("_source"))
    if has_source and reach.get("reachable"):
        return {"verdict": "confirmed", "want_dynamic": True,
                "confidence_reason": "不可信输入无有效净化地到达危险汇聚点，且可达。",
                "poc": rule_poc(c), "remediation": rule_remed(c)}
    # 关键降漏报修复：疑似净化但证据不足 -> SUSPECTED（人工复核），而非直接排除
    return {"verdict": "suspected", "want_dynamic": bool(has_source),
            "confidence_reason": ("路径上疑似存在净化，但无法确证其有效性，需人工复核。" if sanitized
                                   else "存在危险汇聚点但污点/可达性证据不完整，建议人工复核。"),
            "poc": rule_poc(c), "remediation": rule_remed(c)}


async def _persist_finding(ctx, c, verdict, dynamic, confidence, seen_keys):
    rule = rule_by_id(c.get("rule_id", "")) or {}
    vector = rule.get("cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    sev = score_from_vector(vector)
    dedup = _dedup(c)
    if dedup in seen_keys:
        return None
    seen_keys.add(dedup)
    title = f"{rule.get('name', c['vuln_type'])} — {c['location']['file']}:{c['location']['line']}"
    remediation = verdict.get("remediation") or rule.get("remediation", "")
    poc = verdict.get("poc") or (dynamic or {}).get("poc_code") or rule.get("poc_hint", "")
    taint = c.get("taint", {})
    with session_scope() as s:
        f = Finding(task_id=ctx.task_id, vuln_type=c["vuln_type"], title=title, confidence=confidence,
                    severity=sev, cvss_vector=vector, status="open", dedup_key=dedup, remediation=remediation)
        s.add(f); s.flush()
        s.add(EvidenceChain(
            finding_id=f.id,
            entry_point=(c.get("reachability", {}).get("entry_points") or [None])[0],
            source=c.get("_source"), sink=c["location"],
            taint_path=taint.get("taint_path", []), sanitizers=taint.get("sanitizers", []),
            reachability=c.get("reachability", {}),
            static_verdict={"status": verdict["verdict"], "rationale": verdict.get("confidence_reason", ""),
                            "by": "llm" if llm.enabled else "heuristic", "origin": c.get("origin")},
            dynamic_verification=dynamic))
        if poc:
            s.add(Artifact(finding_id=f.id, kind="poc_code", content=str(poc),
                           meta={"reproducible": rule.get("reproducible", False)}))
        if dynamic and dynamic.get("sandbox_log"):
            s.add(Artifact(finding_id=f.id, kind="sandbox_log", content=dynamic["sandbox_log"],
                           meta={"reproduced": dynamic.get("reproduced")}))
            if dynamic.get("request"):
                s.add(Artifact(finding_id=f.id, kind="http_exchange", content=str(dynamic.get("request")), meta={}))
        s.flush()
        fid = f.id
    return {"id": fid, "title": title, "severity": sev}


async def _persist_rejected(ctx, c, reason, seen_keys):
    ctx.state.setdefault("rejected", []).append(
        {"vuln_type": c["vuln_type"], "location": c["location"], "reason": reason})
    dedup = _dedup(c)
    if dedup in seen_keys:
        return
    seen_keys.add(dedup)
    rule = rule_by_id(c.get("rule_id", "")) or {}
    with session_scope() as s:
        f = Finding(task_id=ctx.task_id, vuln_type=c["vuln_type"],
                    title=f"{rule.get('name', c['vuln_type'])} — {c['location']['file']}:{c['location']['line']}",
                    confidence="REJECTED", severity={"level": "info", "score": 0}, status="rejected",
                    dedup_key=dedup)
        s.add(f); s.flush()
        s.add(EvidenceChain(finding_id=f.id, sink=c["location"], source=c.get("_source"),
                            taint_path=(c.get("taint", {}) or {}).get("taint_path", []),
                            reachability=c.get("reachability", {}),
                            static_verdict={"status": "rejected", "rationale": reason}))


def _dedup(c) -> str:
    return hashlib.md5(f"{c['vuln_type']}|{c['location']['file']}|{c['location']['line']}".encode()).hexdigest()[:16]


def _code_window(root, c, ctx_lines: int = 18) -> str:
    try:
        lines = analysis.read_text(root / c["location"]["file"]).splitlines()
        ln = c["location"]["line"]
        a, b = max(0, ln - ctx_lines), min(len(lines), ln + ctx_lines)
        return "\n".join(f"{i+1}: {lines[i]}" for i in range(a, b))[:4000]
    except Exception:
        return c["location"].get("snippet", "")


def _taint_text(c) -> str:
    hops = (c.get("taint", {}) or {}).get("taint_path", [])
    return "\n".join(f"  - {h['location'].get('file')}:{h['location'].get('line')} "
                     f"[{h.get('variable')}] {h.get('transform')}" for h in hops)


def rule_poc(c) -> str:
    return (rule_by_id(c.get("rule_id", "")) or {}).get("poc_hint", "")


def rule_remed(c) -> str:
    return (rule_by_id(c.get("rule_id", "")) or {}).get("remediation", "")
