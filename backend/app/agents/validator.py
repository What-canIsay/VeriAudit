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
from . import prompts, verify_tools
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
    agentic_left = budget.get("agentic_verify_limit", settings.agentic_verify_limit)
    agentic_first = settings.validator_agentic_first
    env = ctx.state.get("env")
    env_ready = bool(env and env.get("ready"))

    cands = sorted(ctx.state.get("candidates", []), key=_priority)
    confirmed = suspected = rejected = dyn = 0
    seen_keys = set()

    for c in cands[:max_verify]:
        if c.get("reachable") is False:
            rejected += 1
            await _persist_rejected(ctx, c, "不可达（无法从对外入口点触达 sink）", seen_keys)
            await ctx.emit("finding.rejected", {"vuln_type": c["vuln_type"], "location": c["location"]})
            continue

        rule = rule_by_id(c.get("rule_id", ""))
        deterministic = c.get("rule_id") in _DETERMINISTIC_RULES or c.get("origin") in ("gitleaks", "osv")

        # The agentic Validator reads cross-file context + drives dynamic tools to build a
        # precise PoC and actually trigger the bug. Two selection strategies (env var):
        #   agentic-first  → try it for EVERY eligible candidate; fall back to legacy only
        #                    when it fails to conclude.
        #   static-first   → legacy judge by default; escalate only for high/critical +
        #                    reproducible candidates.
        # AGENTIC_VERIFY_LIMIT bounds token spend in both (candidates are severity-sorted).
        eligible = (not deterministic and llm.enabled and settings.enable_agentic_verify
                    and env_ready and agentic_left > 0)
        if agentic_first:
            want_agentic = eligible
        else:
            want_agentic = (eligible and rule and rule.get("reproducible")
                            and c.get("_severity") in ("critical", "high"))

        verdict = dynamic = None
        if want_agentic:
            agentic_left -= 1
            await ctx.think(run_id, f"对 {c['vuln_type']} 进行深度核验：读全上下文 + 在常驻应用上实弹复现。")
            verdict, dynamic, ok = await _agentic_verify(ctx, run_id, c, env)
            if not ok:   # agentic produced no conclusion → fall back to legacy logic
                await ctx.think(run_id, f"深度核验未得出结论，回落旧逻辑复核 {c['vuln_type']}。")
                verdict = dynamic = None
        if verdict is None:
            use_llm = llm.enabled and not deterministic and llm_left > 0
            if use_llm:
                llm_left -= 1
            verdict, dynamic = await _legacy_verify(ctx, run_id, c, rule, use_llm, do_dynamic, env, env_ready)

        if verdict["verdict"] == "rejected":
            rejected += 1
            await _persist_rejected(ctx, c, verdict.get("confidence_reason", "静态验证判定不成立"), seen_keys)
            await ctx.emit("finding.rejected", {"vuln_type": c["vuln_type"], "location": c["location"]})
            continue

        if dynamic:
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


async def _legacy_verify(ctx: AuditContext, run_id, c: dict, rule, use_llm: bool,
                         do_dynamic: bool, env, env_ready: bool):
    """The original one-shot static judge + deterministic dynamic probe. Primary path in
    static-first mode; fallback when agentic verify fails. Returns (verdict, dynamic)."""
    verdict = await _static_verify(ctx, run_id, c, use_llm)
    dynamic = None
    want_dyn = verdict.get("want_dynamic", True)
    if verdict["verdict"] != "rejected" and do_dynamic and want_dyn and rule and rule.get("reproducible"):
        if env_ready:
            await ctx.think(run_id, f"向常驻应用环境发起 PoC 复现 {c['vuln_type']} …")
            dynamic = await asyncio.to_thread(sandbox.reproduce_via_env, ctx.root, c, env)
        if dynamic is None:   # no standing env, or env-probe not applicable → ephemeral boot
            await ctx.think(run_id, f"在隔离沙箱中尝试复现 {c['vuln_type']} …")
            dynamic = await asyncio.to_thread(sandbox.try_reproduce, ctx.root, c)
    return verdict, dynamic


async def _agentic_verify(ctx: AuditContext, run_id, c: dict, env: dict):
    """Deep verification: the model reads full context and drives dynamic tools against
    the standing app to build a precise PoC and truly reproduce.
    Returns (verdict, dynamic, ok) — ok=False when the model produced no conclusion
    (ran out of steps / errored) so the caller can fall back to legacy logic."""
    sink = c["location"]
    b = ctx.state.get("budget", {})
    steps = b.get("validator_steps", settings.validator_steps)
    # reuse setup (test creds / login flow / schema) discovered by an earlier candidate,
    # and the persistent cookie jar, so later verifications skip cold-start rediscovery.
    setup = ctx.state.get("verify_setup")
    reuse = (f"\n【可复用的搭建/鉴权上下文（前一漏洞核验已建立，勿重复发现）】：{setup}\n"
             f"容器内 /tmp/vjar 保存着上一次的会话 Cookie，http_probe 会自动携带，可直接复用登录态。\n"
             if setup else "")
    user = (f"待核验候选：{c['vuln_type']}\n位置：{sink['file']}:{sink['line']}\n"
            f"来源：{c.get('origin')}  自评置信度：{c.get('self_confidence')}\n"
            f"发现理由：{c.get('rationale', '')}\n污点线索：\n{_taint_text(c)}\n\n"
            f"sink 附近代码：\n{_code_window(ctx.root, c)}\n\n"
            f"应用已在容器内运行（端口 {env.get('port')}，基础路径 '{env.get('base_path', '')}'）。"
            + reuse +
            f"请深度核验并尽力实弹复现，最后调用 conclude（若你搭建了可复用的账号/会话，请在 setup_notes 中说明）。")
    result: dict = {}

    def on_step(reasoning, content, tool_names):
        ctx.emit_reasoning_sync(run_id, reasoning=reasoning,
                                output=(content if content and not tool_names else None), kind="verify")

    def on_tool(name, args, res):
        if name == "conclude":
            result.update(args or {})
            note = (args or {}).get("setup_notes")
            if note and not ctx.state.get("verify_setup"):
                ctx.state["verify_setup"] = note[:1200]
        summ = {k: res.get(k) for k in ("status", "exit_code", "ok", "note", "reproduced")
                if isinstance(res, dict) and k in res}
        ctx.log_tool_sync(run_id, name, args, summ or {"via": "verify"},
                          ok="error" not in (res or {}))

    finalize_hint = "步数即将用尽，请立即基于现有证据调用 conclude 给出结论（verdict / reproduced / 精确 PoC）。"
    await asyncio.to_thread(lambda: llm.agentic(
        "validator", prompts.VALIDATOR_AGENTIC, user, verify_tools.TOOL_SCHEMAS,
        lambda n, a: verify_tools.dispatch(env, ctx, n, a, sink),
        on_tool=on_tool, on_step=on_step, max_steps=steps, stop_tools={"conclude"},
        finalize_hint=finalize_hint, finalize_at=2,
        timeout=b.get("llm_timeout_sec"), num_retries=b.get("llm_num_retries")))

    v = result.get("verdict")
    if v not in ("confirmed", "suspected", "rejected"):
        v = "suspected"   # ended without a clear verdict → conservative (avoid false-negative)
    verdict = {"verdict": v, "want_dynamic": False,
               "confidence_reason": result.get("confidence_reason")
               or result.get("evidence") or "深度核验：读全上下文并在常驻应用上实弹验证。",
               "poc": result.get("poc", ""), "remediation": result.get("remediation", "")}
    dynamic = None
    if result.get("reproduced"):
        dynamic = {"attempted": True, "reproduced": True, "poc_code": result.get("poc", ""),
                   "request": None, "observation": result.get("evidence") or "验证官在常驻应用上实弹复现成功。",
                   "sandbox_log": (result.get("evidence") or "")[:1800], "reason": None}
    elif result:
        dynamic = {"attempted": True, "reproduced": False,
                   "observation": result.get("confidence_reason") or "未能在预算内实弹复现（静态结论有效）。",
                   "reason": None}
    return verdict, dynamic, bool(result)


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
