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
from ..severity import score_from_vector, valid_cvss
from . import prompts, verify_tools
from .context import AuditContext

_TRUSTED_ORIGINS = {"semgrep", "codeql", "gitleaks", "osv"}
_DETERMINISTIC_RULES = {"hardcoded-secret", "vulnerable-dependency"}

# per-candidate agentic step budget = base B + additive(rank, class, auth, taint).
# extra steps by reproduction difficulty class of the vuln:
_CLASS_STEPS = {
    "path-traversal": 0, "xss": 0, "open-redirect": 0, "ssti": 0, "command-injection": 0,
    "sql-injection": 4, "code-injection": 4, "xxe": 4,
    "ssrf": 8, "deserialization": 8,
}
_CLASS_DEFAULT = 4
_AUTH_PATH_MARKERS = ("admin", "/api/", "auth", "account", "manage", "dashboard", "user")


def _candidate_steps(ctx: AuditContext, c: dict, rank: int) -> int:
    """S_i = B + min(add_i, ADD_MAX). add = rank(small,decaying) + class + auth + taint."""
    b = ctx.state.get("budget", {})
    B = b.get("validator_steps", settings.validator_steps)
    rank_bonus = max(0, 3 - rank)                       # +3/+2/+1 for the first three, then 0
    cls = _CLASS_STEPS.get(c.get("rule_id"), _CLASS_DEFAULT)
    prof = (ctx.state.get("profile_metrics") or {}).get("metrics", {})
    path = (c.get("location", {}).get("file") or "").lower()
    auth = 4 if (prof.get("has_db") and any(m in path for m in _AUTH_PATH_MARKERS)) else 0
    taint = c.get("taint", {}) or {}
    hops = len(taint.get("taint_path", []) or [])
    src = c.get("_source") or {}
    cross_file = bool(src) and src.get("file") != (c.get("location", {}) or {}).get("file")
    taint_bonus = min(3, (2 if cross_file else 0) + (1 if hops >= 4 else 0))
    add = min(rank_bonus + cls + auth + taint_bonus, settings.validator_step_add_max)
    return int(min(B + add, settings.validator_step_hard_cap))


def _priority(c):
    return (-SEVERITY_ORDER.get(c.get("_severity", "medium"), 0), -c.get("self_confidence", 0))


async def run(ctx: AuditContext) -> dict:
    run_id = await ctx.start_agent("validator", "verify")
    budget = ctx.state.get("plan", {}).get("budget", {}) or ctx.state.get("budget", {})
    max_verify = budget.get("max_verify", settings.max_verify)
    S = {
        "run_id": run_id,
        "do_dynamic": budget.get("dynamic_verification", False),
        "llm_left": budget.get("llm_triage_limit", settings.llm_triage_limit),
        "agentic_left": budget.get("agentic_verify_limit", settings.agentic_verify_limit),
        "agentic_first": settings.validator_agentic_first,
        "limit_on": settings.enable_agentic_verify_limit,   # off ⇒ no quota on agentic verify
        "env": ctx.state.get("env"),
        "confirmed": 0, "suspected": 0, "rejected": 0, "dyn": 0,
        "seen_keys": set(),
    }
    S["env_ready"] = bool(S["env"] and S["env"].get("ready"))

    cands = sorted(ctx.state.get("candidates", []), key=_priority)
    # preheat-discovered incidentals are already in `cands` (processed via this snapshot) —
    # reset the pending queue so they aren't ALSO drained a second time.
    ctx.state["incidental_pending"] = []
    # late arrivals (e.g. preheat incidentals) skipped the Tracer → enrich before verifying.
    for c in cands:
        if "reachability" not in c:
            await _enrich_candidate(ctx, c)

    # growable verify queue: incidentals discovered DURING verification get appended and
    # independently verified in the same loop (bounded by inc_cap so it can't run away).
    queue = list(cands[:max_verify])
    inc_cap = max(3, max_verify // 4)
    inc_used = 0
    rank = 0
    while rank < len(queue):
        await _process_candidate(ctx, queue[rank], rank, S)
        for nc in ctx.state.pop("incidental_pending", []) or []:
            if inc_used >= inc_cap:
                break
            await _enrich_candidate(ctx, nc)
            queue.append(nc)
            inc_used += 1
        rank += 1

    out = {"confirmed": S["confirmed"], "suspected": S["suspected"], "rejected": S["rejected"],
           "dynamic_reproduced": S["dyn"], "incidental": inc_used}
    await ctx.emit("verify.ready", out)
    await ctx.finish_agent(run_id, out)
    return out


async def _enrich_candidate(ctx: AuditContext, c: dict) -> None:
    """Give a candidate that skipped the Tracer (incidental / preheat-found) the same
    source + heuristic taint + laddered reachability metadata the verify logic expects."""
    from . import tracer
    from .. import callgraph
    if c.get("_source") is None:
        await asyncio.to_thread(tracer._enrich_source, ctx.root, c)
    taint = await asyncio.to_thread(analysis.taint_trace, ctx.root, c)
    reach = await asyncio.to_thread(callgraph.reachability, ctx.root, c, ctx.state.get("entrypoints", []))
    c["taint"] = taint
    c["reachability"] = reach
    c["reachable"] = reach.get("reachable")


async def _process_candidate(ctx: AuditContext, c: dict, rank: int, S: dict) -> None:
    """Verify ONE candidate (agentic → legacy fallback), persist the finding, update S."""
    run_id = S["run_id"]
    if c.get("reachable") is False:
        S["rejected"] += 1
        await _persist_rejected(ctx, c, "不可达（无法从对外入口点触达 sink）", S["seen_keys"])
        await ctx.emit("finding.rejected", {"vuln_type": c["vuln_type"], "location": c["location"]})
        return

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
                and S["env_ready"] and (not S["limit_on"] or S["agentic_left"] > 0))
    if S["agentic_first"]:
        want_agentic = eligible
    else:
        want_agentic = (eligible and rule and rule.get("reproducible")
                        and c.get("_severity") in ("critical", "high"))

    verdict = dynamic = None
    if want_agentic:
        S["agentic_left"] -= 1
        steps = _candidate_steps(ctx, c, rank)
        await ctx.think(run_id, f"对 {c['vuln_type']} 进行深度核验（预算 {steps} 步）：读全上下文 + 在常驻应用上实弹复现。")
        verdict, dynamic, ok = await _agentic_verify(ctx, run_id, c, S["env"], steps)
        if not ok:   # agentic stuck early with no progress → fall back to legacy logic
            await ctx.think(run_id, f"深度核验未取得进展，回落旧逻辑复核 {c['vuln_type']}。")
            verdict = dynamic = None
    if verdict is None:
        use_llm = llm.enabled and not deterministic and S["llm_left"] > 0
        if use_llm:
            S["llm_left"] -= 1
        verdict, dynamic = await _legacy_verify(ctx, run_id, c, rule, use_llm,
                                                S["do_dynamic"], S["env"], S["env_ready"])

    if verdict["verdict"] == "rejected":
        S["rejected"] += 1
        await _persist_rejected(ctx, c, verdict.get("confidence_reason", "静态验证判定不成立"), S["seen_keys"])
        await ctx.emit("finding.rejected", {"vuln_type": c["vuln_type"], "location": c["location"]})
        return

    if dynamic:
        await ctx.emit("sandbox.poc_attempt", {"vuln_type": c["vuln_type"],
                                               "attempted": dynamic.get("attempted"),
                                               "reproduced": dynamic.get("reproduced")})

    if dynamic and dynamic.get("reproduced"):
        confidence = "CONFIRMED_DYNAMIC"; S["confirmed"] += 1; S["dyn"] += 1
    elif verdict["verdict"] == "confirmed":
        confidence = "CONFIRMED_STATIC"; S["confirmed"] += 1
    else:
        confidence = "SUSPECTED"; S["suspected"] += 1

    finding = await _persist_finding(ctx, c, verdict, dynamic, confidence, S["seen_keys"])
    if finding:
        await ctx.emit("finding.confirmed", {"finding_id": finding["id"], "vuln_type": c["vuln_type"],
                                             "confidence": confidence, "severity": finding["severity"],
                                             "title": finding["title"]})


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


async def _agentic_verify(ctx: AuditContext, run_id, c: dict, env: dict, steps: int):
    """Deep verification: the model reads full context and drives dynamic tools against
    the standing app to build a precise PoC and truly reproduce.

    Returns (verdict, dynamic, ok). ok=False ONLY when the session made no real progress
    (stuck early) → caller falls back to legacy. A "promising" session that runs out gets
    a one-time 1.5× extension; if it still doesn't conclude but DID attempt exploitation,
    its partial result is salvaged as SUSPECTED (ok=True) instead of a cold legacy pass."""
    from collections import deque
    sink = c["location"]
    b = ctx.state.get("budget", {})
    # reuse the preheat/earlier setup (test creds, role sessions, schema, cookie jars).
    setup = ctx.state.get("verify_setup")
    sessions = ctx.state.get("verify_sessions") or {}
    reuse = ""
    if setup or sessions:
        reuse = f"\n【可复用的预热/搭建上下文（勿重复发现）】：{setup or ''}\n"
        if sessions:
            reuse += (f"已就绪的角色会话（http_probe 传 session=对应名即可复用登录态，无需重登）：{sessions}\n")
    reach = c.get("reachability", {}) or {}
    cg_path = reach.get("path")
    cg_line = (f"调用图确认的可达路径（入口→sink）：{' → '.join(h.get('function','?') for h in cg_path)}\n"
               if cg_path else "")
    # for logic-class candidates, give the model the framework's security model + the
    # class-specific "how to spot / how to confirm" so it can reproduce access-control bugs.
    _rule = rule_by_id(c.get("rule_id", "")) or {}
    fw_note = ""
    if _rule.get("class") == "logic":
        fw_note = (f"\n【这是逻辑类漏洞：{_rule.get('how_to_spot', '')}】"
                   f"确认思路：{_rule.get('poc_hint', '')}\n"
                   + (ctx.state.get("framework_guidance") or ""))
    env_line = _env_desc(env)
    user = (f"待核验候选：{c['vuln_type']}\n位置：{sink['file']}:{sink['line']}\n"
            f"来源：{c.get('origin')}  自评置信度：{c.get('self_confidence')}\n"
            f"发现理由：{c.get('rationale', '')}\n污点线索：\n{_taint_text(c)}\n{cg_line}\n"
            f"sink 附近代码：\n{_code_window(ctx.root, c)}\n{fw_note}\n"
            f"{env_line}"
            + reuse +
            f"请深度核验并尽力实弹复现，最后调用 conclude（若你新建了可复用的账号/会话，请在 setup_notes 中说明）。")
    result: dict = {}
    recent = deque(maxlen=4)        # rolling "did an exploit action succeed" window
    progress = {"did_exploit": False, "last": ""}

    def _exploit(name, args, res):
        if not isinstance(res, dict):
            return False
        if name in ("http_probe", "sql_log"):
            return "error" not in res and res.get("exit_code", 0) != -1
        if name == "net_send":                       # non-HTTP protocol interaction
            return res.get("ok") is True
        if name == "run_target":                     # native/CLI repro — a crash IS progress
            return "error" not in res
        if name == "run_command":
            cmd = (args.get("cmd") or "").lower()
            if any(k in cmd for k in ("sqlmap", "nuclei", "curl", "mysql", "nc ",
                                      "-fsanitize", "gdb", "./")):
                return res.get("exit_code", 0) != -1
        return False

    def on_step(reasoning, content, tool_names):
        if content and not tool_names:
            progress["last"] = content
        ctx.emit_reasoning_sync(run_id, reasoning=reasoning,
                                output=(content if content and not tool_names else None), kind="verify")

    def on_tool(name, args, res):
        if name == "conclude":
            result.update(args or {})
            note = (args or {}).get("setup_notes")
            if note and not ctx.state.get("verify_setup"):
                ctx.state["verify_setup"] = str(note)[:1200]
        ex = _exploit(name, args, res)
        if ex:
            progress["did_exploit"] = True
        recent.append(ex)
        summ = {k: res.get(k) for k in ("status", "exit_code", "ok", "note", "reproduced")
                if isinstance(res, dict) and k in res}
        ctx.log_tool_sync(run_id, name, args, summ or {"via": "verify"},
                          ok="error" not in (res or {}))

    finalize_hint = "步数即将用尽，请立即基于现有证据调用 conclude 给出结论（verdict / reproduced / 精确 PoC）。"
    await asyncio.to_thread(lambda: llm.agentic(
        "validator", prompts.VALIDATOR_AGENTIC, user, verify_tools.active_schemas(),
        lambda n, a: verify_tools.dispatch(env, ctx, n, a, sink),
        on_tool=on_tool, on_step=on_step, max_steps=steps, stop_tools={"conclude"},
        finalize_hint=finalize_hint, finalize_at=2,
        timeout=b.get("llm_timeout_sec"), num_retries=b.get("llm_num_retries"),
        extend_when=lambda: any(recent), extend_factor=settings.validator_step_extension,
        extend_hard_cap=settings.validator_step_hard_cap, checkpoint=ctx.control.checkpoint))

    if result:   # model concluded
        v = result.get("verdict")
        if v not in ("confirmed", "suspected", "rejected"):
            v = "suspected"
        verdict = {"verdict": v, "want_dynamic": False,
                   "confidence_reason": result.get("confidence_reason")
                   or result.get("evidence") or "深度核验：读全上下文并在常驻应用上实弹验证。",
                   "poc": result.get("poc", ""), "remediation": result.get("remediation", ""),
                   "cvss_vector": result.get("cvss_vector")}   # per-instance CVSS from the model
        if result.get("reproduced"):
            dynamic = {"attempted": True, "reproduced": True, "poc_code": result.get("poc", ""),
                       "request": None, "observation": result.get("evidence") or "验证官在常驻应用上实弹复现成功。",
                       "sandbox_log": (result.get("evidence") or "")[:1800], "reason": None}
        else:
            dynamic = {"attempted": True, "reproduced": False,
                       "observation": result.get("confidence_reason") or "未能在预算内实弹复现（静态结论有效）。",
                       "reason": None}
        return verdict, dynamic, True

    if progress["did_exploit"]:   # salvage: attempted exploitation but ran out → SUSPECTED
        verdict = {"verdict": "suspected", "want_dynamic": False,
                   "confidence_reason": "深度核验已实弹尝试但未在步数内下最终结论；据现有进展保守判疑似，附部分证据。",
                   "poc": (progress["last"] or "")[:1500], "remediation": ""}
        dynamic = {"attempted": True, "reproduced": False,
                   "observation": "实弹尝试进行中被步数截断（已保留部分证据，未冷跑旧逻辑）。", "reason": None}
        return verdict, dynamic, True

    return {"verdict": "suspected", "want_dynamic": False, "confidence_reason": "",
            "poc": "", "remediation": ""}, None, False   # stuck early → caller falls back


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
    # per-instance severity: use the CVSS vector the Validator tailored to THIS finding
    # (auth/exposure/scope/impact) when it's well-formed; else fall back to the class default.
    model_vec = (verdict or {}).get("cvss_vector")
    vector = model_vec if valid_cvss(model_vec) else \
        rule.get("cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
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


def _env_desc(env: dict) -> str:
    """Describe the standing target to the Validator by kind, so it reaches for the right
    exploit primitive (http_probe vs net_send vs run_target)."""
    env = env or {}
    kind = (env.get("target_kind") or "http").lower()
    if kind == "network":
        proto = (env.get("proto") or "tcp").lower()
        return (f"目标是【网络守护进程】，已在容器内监听 127.0.0.1:{env.get('port')}（{proto}，非 HTTP）。"
                f"用 net_send(port={env.get('port')}, proto='{proto}', payload=...) 发送自定义协议报文来交互与复现；http_probe 不适用。")
    if kind == "cli":
        tc = env.get("target_cmd") or "（见项目构建产物）"
        note = env.get("build_note")
        note_line = f"\n【环境搭建官的构建交接】{note}" if note else ""
        return (f"目标是【原生/CLI/库类程序】，无常驻服务。运行目标的方式：{tc}。"
                f"用 run_target(cmd=..., stdin/stdin_b64/input_files=...) 喂构造好的畸形输入实弹复现——"
                f"触发 SIGSEGV/SIGABRT 或 ASan/UBSan 报告即为决定性证据。"
                f"【复现精度按项目规模选】：小项目可 -fsanitize=address,undefined -g 全量重编；"
                f"大型项目（如 Node）【别整树重编】，只针对可疑源文件编一个最小 harness 叠 ASan，"
                f"或用现成二进制 + gdb -batch 观察崩溃栈帧（无 ASan 也是决定性证据）。{note_line}")
    return (f"目标应用已在容器内运行（HTTP，端口 {env.get('port')}，基础路径 '{env.get('base_path', '')}'）。"
            f"用 http_probe 发精确请求复现。")


def _taint_text(c) -> str:
    taint = c.get("taint", {}) or {}
    hops = taint.get("taint_path", [])
    lines = [f"  - {h['location'].get('file')}:{h['location'].get('line')} "
             f"[{h.get('variable')}] {h.get('transform')}" for h in hops]
    sem = taint.get("semantic")
    if sem:
        lines.append(
            f"  - 【语义污点·{sem.get('engine')}】source→sink 数据流="
            f"{sem.get('tainted_flow')}（flow_count={sem.get('flow_count')}）"
            f"—— 由数据流引擎判定，比启发式更强；但'no'可能是漏边，不等于安全。")
    return "\n".join(lines) if lines else "  - （无污点路径信息）"


def rule_poc(c) -> str:
    return (rule_by_id(c.get("rule_id", "")) or {}).get("poc_hint", "")


def rule_remed(c) -> str:
    return (rule_by_id(c.get("rule_id", "")) or {}).get("remediation", "")
