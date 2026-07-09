"""VeriAudit RAG — semantic + lexical code retrieval over the target project.

Public API (used by Recon to build the index and by the Hunter/Validator tools to query):
  · available()          -> bool                     (ENABLE_RAG)
  · index(root, ...)     -> dict                      (build or incrementally update)
  · search(root, q, k)   -> {"available", "results":[...], "backend", ...}
  · status(root)         -> {"available","backend","semantic","chunks","degraded","reason"}

The index is built once per project (incremental on rebuild), cached in-process, and
persisted under _data/rag/<hash>/. Embedding backend is resolved by config
(fastembed semantic by default, deterministic hashing fallback offline).
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from ..config import settings
from .embeddings import get_embedder, is_semantic
from .indexer import Index
from .retriever import search as _search

_CACHE: dict = {}          # str(root) -> Index
_EMBED_ERR: dict = {}      # str(root) -> str (backend-load error, for status)


def available() -> bool:
    return bool(getattr(settings, "enable_rag", True))


def _embedder():
    return get_embedder(getattr(settings, "rag_embed_backend", "auto"))


def _get_index(root: Path, build: bool = True, progress: Optional[Callable] = None) -> Optional[Index]:
    key = str(root)
    idx = _CACHE.get(key)
    if idx is None:
        try:
            idx = Index(Path(root), _embedder())
        except Exception as e:                       # embedder failed to load entirely
            _EMBED_ERR[key] = str(e)[:200]
            return None
        if not idx.load() and build:
            idx.build_or_update(progress=progress)
        _CACHE[key] = idx
    return idx


def index(root: Path, force: bool = False, progress: Optional[Callable] = None) -> dict:
    """Build or incrementally update the index for `root`. force=True drops the in-process
    cache first (still reuses the on-disk index if compatible)."""
    if not available():
        return {"available": False, "reason": "ENABLE_RAG=false"}
    key = str(root)
    if force:
        _CACHE.pop(key, None)
    try:
        idx = Index(Path(root), _embedder())
    except Exception as e:
        _EMBED_ERR[key] = str(e)[:200]
        return {"available": False, "reason": f"嵌入后端加载失败：{str(e)[:150]}"}
    stats = idx.build_or_update(progress=progress)
    _CACHE[key] = idx
    stats["available"] = True
    stats["semantic"] = is_semantic(idx.embedder)
    return stats


def search(root: Path, query: str, k: Optional[int] = None, hybrid_alpha: Optional[float] = None) -> dict:
    if not available():
        return {"available": False, "reason": "ENABLE_RAG=false", "results": []}
    idx = _get_index(root, build=True)
    if idx is None:
        return {"available": False, "results": [],
                "reason": f"嵌入后端不可用：{_EMBED_ERR.get(str(root), '未知')}"}
    k = int(k or getattr(settings, "rag_top_k", 8))
    alpha = float(hybrid_alpha if hybrid_alpha is not None else getattr(settings, "rag_hybrid_alpha", 0.7))
    results = _search(idx, query, k=k, hybrid_alpha=alpha)
    return {"available": True, "backend": idx.embedder.name,
            "semantic": is_semantic(idx.embedder), "chunks": len(idx.chunks),
            "count": len(results), "results": [r.to_dict() for r in results],
            "note": ("检索基于代码块的语义相似度；命中块给出 file:line，请 read_file 核实全文再下判断。"
                     if is_semantic(idx.embedder) else
                     "【降级】当前为词法(hashing)检索而非神经语义——按关键词/子词重叠匹配，"
                     "召回不如真语义；装 fastembed 或配置云端嵌入可提升。命中块请 read_file 核实。")}


def status(root: Path) -> dict:
    """Report RAG availability + which embedding backend actually runs (for the UI degrade
    banner). Does NOT build the index (cheap)."""
    if not available():
        return {"available": False, "backend": None, "semantic": False,
                "degraded": True, "reason": "ENABLE_RAG=false（已关闭语义检索）", "chunks": 0}
    try:
        emb = _embedder()
    except Exception as e:
        return {"available": False, "backend": None, "semantic": False, "degraded": True,
                "reason": f"嵌入后端加载失败：{str(e)[:150]}", "chunks": 0}
    idx = _CACHE.get(str(root))
    chunks = len(idx.chunks) if idx is not None else 0
    semantic = is_semantic(emb)
    return {"available": True, "backend": emb.name, "semantic": semantic,
            "degraded": (not semantic),
            "reason": ("" if semantic else
                       "语义嵌入(fastembed/云端)不可用，回落词法 hashing 检索（召回弱于真语义）。"),
            "chunks": chunks}
