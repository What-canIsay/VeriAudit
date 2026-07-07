"""Hunter (漏洞猎手): 高召回候选发现 = SAST候选池 + LLM语义发现 + 知识库。"""
from __future__ import annotations

import asyncio
import json

from .. import analysis
from ..config import settings
from ..db import session_scope
from ..llm.gateway import llm
from ..models import Candidate
from . import prompts, tools
from .context import AuditContext


async def run(ctx: AuditContext) -> dict:
    run_id = await ctx.start_agent("hunter", "hunt")
    plan = ctx.state.get("plan", {})

    # 1) 确定性候选池（规则 + 可选 Semgrep）
    await ctx.think(run_id, "运行确定性检测：知识库规则匹配危险汇聚点 (scan_candidates)。")
    cands = await asyncio.to_thread(analysis.scan_candidates, ctx.root)
    await ctx.log_tool(run_id, "scan_candidates", {}, {"count": len(cands)})

    if settings.enable_semgrep:
        sg = await asyncio.to_thread(analysis.run_semgrep, ctx.root)
        if sg:
            await ctx.log_tool(run_id, "semgrep_scan", {}, {"count": len(sg)})
            cands = _merge(cands, sg)

    # 2) LLM 语义高召回增强（工具调用探索），失败自动跳过
    if llm.enabled and plan.get("budget", {}).get("llm_augment"):
        await ctx.think(run_id, "调用 LLM 阅读代码，补充规则遗漏的语义/逻辑类候选（高召回）。")
        extra = await _llm_augment(ctx, run_id)
        if extra:
            cands = _merge(cands, extra)

    cap = plan.get("budget", {}).get("max_candidates", settings.max_candidates)
    cands = cands[:cap]

    # 3) 落库并写入状态
    for c in cands:
        with session_scope() as s:
            row = Candidate(task_id=ctx.task_id, vuln_type=c["vuln_type"],
                            location=c["location"], self_confidence=c["self_confidence"],
                            rationale=c["rationale"], origin=c["origin"])
            s.add(row)
            s.flush()
            c["db_id"] = row.id
        await ctx.emit("candidate.recorded", {
            "vuln_type": c["vuln_type"], "location": c["location"],
            "self_confidence": c["self_confidence"], "origin": c["origin"]})

    ctx.state["candidates"] = cands
    out = {"candidates": len(cands),
           "by_origin": _count(cands, "origin")}
    await ctx.finish_agent(run_id, out)
    return out


async def _llm_augment(ctx: AuditContext, run_id: str):
    user = ("请审计该项目，寻找基于规则可能遗漏的语义/逻辑漏洞候选（认证授权、越权、业务逻辑、"
            "跨文件数据流等）。先用工具阅读关键文件，然后仅输出一个 JSON 数组，每项："
            "{\"vuln_type\":\"CWE-xxx 名称\",\"file\":\"相对路径\",\"line\":整数,"
            "\"confidence\":0-1,\"rationale\":\"理由\"}。至多 8 条。")

    def on_tool(name, args, result):
        # fire-and-forget logging is done post-hoc below to keep loop sync
        ctx.state.setdefault("_hunter_tools", []).append({"tool": name, "args": args})

    try:
        text, trace = await asyncio.to_thread(
            llm.agentic, "hunter", prompts.HUNTER, user,
            tools.TOOL_SCHEMAS, lambda n, a: tools.dispatch(ctx.root, n, a),
            on_tool, 6)
    except Exception:
        return []

    for t in (ctx.state.pop("_hunter_tools", []) or []):
        await ctx.log_tool(run_id, t["tool"], t["args"], {"via": "llm"}, True)

    if not text:
        return []
    try:
        import re
        m = re.search(r"\[.*\]", text, re.S)
        arr = json.loads(m.group(0)) if m else json.loads(text)
    except Exception:
        return []
    out = []
    for item in arr[:8]:
        try:
            out.append({
                "rule_id": "llm-semantic", "vuln_type": item["vuln_type"],
                "_severity": "high", "origin": "llm",
                "self_confidence": float(item.get("confidence", 0.5)),
                "rationale": "LLM 语义发现：" + item.get("rationale", ""),
                "location": {"file": item["file"], "line": int(item.get("line", 1)),
                             "function": None, "snippet": ""},
                "lang": "unknown", "_source": None, "_sanitized": False,
            })
        except Exception:
            continue
    return out


def _merge(base, extra):
    seen = {(c["vuln_type"], c["location"]["file"], c["location"]["line"]) for c in base}
    for c in extra:
        k = (c["vuln_type"], c["location"]["file"], c["location"]["line"])
        if k not in seen:
            base.append(c)
            seen.add(k)
    return base


def _count(items, field):
    out = {}
    for it in items:
        out[it.get(field, "?")] = out.get(it.get(field, "?"), 0) + 1
    return out
