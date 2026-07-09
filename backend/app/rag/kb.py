"""Semantic + keyword HYBRID retrieval over the built-in vulnerability knowledge base.

The KB (knowledge.VULN_RULES) is small and global, so we embed it once (cached in-process).
`search()` blends semantic similarity with keyword overlap — so the agent gets BOTH modalities
(RAG for meaning, keyword for exact class/CWE hits). When RAG is disabled or the embedder
can't load, it degrades to pure keyword lookup (knowledge.kb_lookup) so the tool always works.

This is GENERAL vulnerability knowledge (cause / exploit / fix), NOT the audited project's
code — project code lives behind search_code / search_code_semantic.
"""
from __future__ import annotations

import numpy as np

from ..config import settings
from .embeddings import _tokens, is_semantic, shared_embedder

_KB = None   # {"name": embedder_name, "matrix": ndarray(n,dim), "entries": [dict]}


def _entry_text(r: dict) -> str:
    return f"{r['name']} {r['cwe']} {r['id']}。利用：{r.get('poc_hint', '')} 修复：{r.get('remediation', '')}"


def _entries() -> list:
    from ..knowledge import VULN_RULES
    return [{"id": r["id"], "cwe": r["cwe"], "name": r["name"],
             "remediation": r["remediation"], "poc_hint": r["poc_hint"],
             "_text": _entry_text(r)} for r in VULN_RULES]


def _ensure_index(emb) -> dict:
    global _KB
    if _KB is not None and _KB["name"] == emb.name:
        return _KB
    ents = _entries()
    _KB = {"name": emb.name, "matrix": emb.embed([e["_text"] for e in ents]), "entries": ents}
    return _KB


def _keyword_only(query: str, k: int) -> dict:
    from ..knowledge import kb_lookup
    return {"available": True, "semantic": False, "results": kb_lookup(query)[:k],
            "note": "知识库【关键词】检索（RAG 关闭或嵌入不可用）。这是通用漏洞知识，非本项目代码。"}


def search(query: str = "", vuln_type: str = "", k: int = 5) -> dict:
    q = (query + " " + vuln_type).strip()
    if not getattr(settings, "enable_rag", True):
        return _keyword_only(q, k)
    try:
        emb = shared_embedder()
        kbx = _ensure_index(emb)
    except Exception:
        return _keyword_only(q, k)

    qtoks = set(_tokens(q)) if q else set()
    if q:
        qv = emb.embed_query(q)
        sims = kbx["matrix"] @ qv
    else:
        sims = np.zeros(len(kbx["entries"]), dtype=np.float32)

    scored = []
    for i, e in enumerate(kbx["entries"]):
        etoks = set(_tokens(f"{e['name']} {e['id']} {e['cwe']}"))
        kw = (len(qtoks & etoks) / len(qtoks)) if qtoks else 0.0
        score = 0.65 * float(sims[i]) + 0.35 * kw
        scored.append((score, e))
    scored.sort(key=lambda x: -x[0])
    top = [{"id": e["id"], "cwe": e["cwe"], "name": e["name"],
            "remediation": e["remediation"], "poc_hint": e["poc_hint"], "score": round(s, 3)}
           for s, e in scored[:k]]
    return {"available": True, "semantic": is_semantic(emb), "backend": emb.name, "results": top,
            "note": "知识库【语义+关键词】混合检索（漏洞成因/利用/修复）。这是通用漏洞知识，"
                    "不是本项目代码——具体项目代码用 search_code / search_code_semantic。"}
