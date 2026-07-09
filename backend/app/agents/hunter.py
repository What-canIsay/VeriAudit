"""Hunter (漏洞猎手): the audit's autonomous core.

Cloud mode  : the MODEL drives — it orchestrates the professional toolset
              (semgrep/codeql/secret/dependency/dataflow/read/search) and records
              candidates via report_candidate. Its reasoning + tool choices stream
              live to the UI. Scanner results it gathered are not discarded.
Mock mode   : deterministic fallback — regex detector + any available scanners.
"""
from __future__ import annotations

import asyncio

from .. import analysis, scanners
from ..config import settings
from ..db import session_scope
from ..llm.gateway import llm
from ..models import Candidate
from . import prompts, tools
from .context import AuditContext


async def run(ctx: AuditContext) -> dict:
    run_id = await ctx.start_agent("hunter", "hunt")
    plan = ctx.state.get("plan", {})
    cap = plan.get("budget", {}).get("max_candidates", settings.max_candidates)

    if llm.enabled:
        await ctx.think(run_id, "以资深审计员的方式自主编排专业工具进行漏洞挖掘（模型主导）。")
        await asyncio.to_thread(_llm_hunt, ctx, run_id)
        # Trust the model's curated report_candidate list (it already judged scanner
        # output and excluded noise). Only fall back if it produced nothing at all.
        ctx.state.setdefault("candidates", [])
        if not ctx.state.get("candidates"):
            note = "模型未产出候选" + (f"（LLM 错误：{llm.last_error}）" if llm.last_error else "")
            await ctx.think(run_id, note + "，回落确定性检测器 + 专业扫描器兜底。")
            pool = await asyncio.to_thread(_deterministic_pool, ctx)
            _merge(ctx.state["candidates"], pool)
    else:
        await ctx.think(run_id, "Mock 模式：运行确定性检测器 + 可用的专业扫描器（规则 / Semgrep / Gitleaks / OSV）。")
        pool = await asyncio.to_thread(_deterministic_pool, ctx)
        _merge(ctx.state.setdefault("candidates", []), pool)

    cands = ctx.state.get("candidates", [])[:cap]
    ctx.state["candidates"] = cands

    for c in cands:
        if not c.get("db_id"):
            with session_scope() as s:
                row = Candidate(task_id=ctx.task_id, vuln_type=c["vuln_type"],
                                location=c["location"], self_confidence=c.get("self_confidence", 0.5),
                                rationale=c.get("rationale", ""), origin=c.get("origin", "llm"))
                s.add(row)
                s.flush()
                c["db_id"] = row.id
            if c.get("origin") != "llm":   # llm candidates already emitted live via report_candidate
                await ctx.emit("candidate.recorded", {
                    "vuln_type": c["vuln_type"], "location": c["location"],
                    "self_confidence": c.get("self_confidence", 0.5), "origin": c.get("origin")})

    out = {"candidates": len(cands), "by_origin": _count(cands, "origin")}
    await ctx.finish_agent(run_id, out)
    return out


_CG_ENGINE_DESC = {
    "codeql": "CodeQL（语义级数据流，精度最高）",
    "joern": "Joern（CPG 跨过程，精度高、多语言）",
    "treesitter": "Tree-sitter（按函数名解析，精度有限、可能有较多假边——尤其要 read_file 核实）",
}


def _callgraph_status_line(ctx: AuditContext) -> str:
    """Tell the Hunter whether the call graph built and, if so, WHICH engine — so it
    calibrates how much to trust cg_* results."""
    cg = ctx.state.get("callgraph_status") or {}
    eng = cg.get("engine")
    if eng in _CG_ENGINE_DESC:
        return (f"【调用图状态】构建成功，绘图引擎 = {_CG_ENGINE_DESC[eng]}。"
                f"可用 cg_overview / cg_callers / cg_callees / cg_path / cg_subgraph / cg_dataflow / check_reachability 查询；"
                f"但图不保证正确，任何结论务必 read_file 核实，且『不可达』不代表安全。\n")
    return ("【调用图状态】构建失败 / 不可用：cg_* 工具会返回 unavailable，"
            "请直接用 read_file / search_code / check_reachability 判断可达性，不要依赖调用图。\n")


def _llm_hunt(ctx: AuditContext, run_id: str) -> None:
    profile = ctx.state.get("profile", {})
    eps = ctx.state.get("entrypoints", [])
    langs = profile.get("languages", {})
    top = sorted({loc for e in eps for loc in [e["location"]["file"]]})[:12]
    focus = (ctx.state.get("plan", {}) or {}).get("focus")
    attack_surface = ctx.state.get("attack_surface")
    guidance = ""
    if focus:
        guidance += f"【编排官下发的审计重点，请优先据此开挖（但不局限于此）】{focus}\n"
    if attack_surface:
        guidance += f"【侦察员研判的攻击面】{attack_surface}\n"
    user = (f"项目语言分布：{langs}；已识别对外入口点 {len(eps)} 个。"
            f"部分入口文件：{top}。\n"
            + guidance
            + _callgraph_status_line(ctx) +
            f"请以资深审计员的方式自主审计本项目，发现真实安全漏洞，并对每个可疑点调用 report_candidate 登记。"
            f"你可自由决定调用哪些工具、以什么顺序进行。")

    def on_step(reasoning, content, tool_names):
        ctx.emit_reasoning_sync(run_id, reasoning=reasoning,
                                output=(content if content and not tool_names else None), kind="hunt")

    def on_tool(name, args, result):
        summary = {k: result.get(k) for k in ("count", "engine", "ok", "recorded", "reachability")
                   if isinstance(result, dict) and k in result}
        ctx.log_tool_sync(run_id, name, args, summary or {"via": "llm"}, ok="error" not in (result or {}))

    budget = ctx.state.get("budget", {})
    finalize_hint = ("步数即将用尽。请【立即停止探索、不要再读取新文件】，"
                     "现在就对你已经识别到的每一个可疑漏洞调用 report_candidate 逐个登记"
                     "（可连续多次调用）。宁可多报，下游有独立验证。")
    llm.agentic("hunter", prompts.HUNTER, user, tools.active_schemas(),
                lambda n, a: tools.dispatch(ctx, n, a),
                on_tool=on_tool, on_step=on_step,
                max_steps=budget.get("llm_hunt_steps", settings.llm_hunt_steps),
                finalize_hint=finalize_hint, finalize_at=3,
                timeout=budget.get("llm_timeout_sec"), num_retries=budget.get("llm_num_retries"))


def _deterministic_pool(ctx: AuditContext):
    root = ctx.root
    pool = analysis.scan_candidates(root)
    if settings.enable_semgrep:
        pool = _merge(pool, scanners.run_semgrep(root))
    if settings.enable_secret_scan:
        pool = _merge(pool, scanners.run_gitleaks(root))
    if settings.enable_dependency_scan:
        pool = _merge(pool, scanners.run_osv(root))
    return pool


def _from_scan_cache(ctx: AuditContext):
    out = []
    for key in ("semgrep", "codeql", "gitleaks", "osv"):
        val = ctx.state.get("_scan_cache", {}).get(key)
        if isinstance(val, list):
            out.extend(val)
    return out


def _cwe(vt: str) -> str:
    import re
    m = re.search(r"CWE-(\d+)", vt or "")
    return m.group(1) if m else (vt or "?")


def _merge(base, extra):
    # dedup across scanners by (CWE, file, line) so the same issue found by multiple
    # tools / rule labels collapses to one candidate.
    seen = {(_cwe(c["vuln_type"]), c["location"]["file"], c["location"]["line"]) for c in base}
    for c in extra or []:
        k = (_cwe(c["vuln_type"]), c["location"]["file"], c["location"]["line"])
        if k not in seen:
            base.append(c)
            seen.add(k)
    return base


def _count(items, field):
    out = {}
    for it in items:
        out[it.get(field, "?")] = out.get(it.get(field, "?"), 0) + 1
    return out
