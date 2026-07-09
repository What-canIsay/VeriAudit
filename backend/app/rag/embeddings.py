"""Pluggable embedding backends for RAG.

Three backends behind one interface (all return L2-normalized float32 vectors, so cosine
similarity == dot product):

  · fastembed  — REAL semantic embeddings, ONNX (no torch), fully OFFLINE after a one-time
                 model download to the D-drive cache. This is the default when installed.
  · cloud      — the configured LLM provider's embedding model via LiteLLM (costs money /
                 network egress). Only used when explicitly selected.
  · hashing    — deterministic, dependency-free lexical vectorizer (word + camel/snake
                 subword features, stable hashing). Not neural, but always available and
                 reproducible — the honest offline fallback + what the hermetic tests use.

`get_embedder()` picks a backend; the returned object exposes `.name` (e.g.
"fastembed:BAAI/bge-small-en-v1.5" / "hashing:d512") so the index can version itself by it
and the UI can report which one actually ran (degradation transparency).
"""
from __future__ import annotations

import hashlib
import re
from typing import List, Optional

import numpy as np

from ..config import settings


# --------------------------------------------------------------------------- #
def _stable_hash(s: str) -> int:
    # process-stable (unlike builtin hash()) so identical text → identical vector across
    # restarts — required for incremental indexing to detect "unchanged".
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8", "replace"), digest_size=8).digest(), "little")


_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[^\sA-Za-z0-9_]")
_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z]+|[0-9]+")


def _tokens(text: str) -> List[str]:
    """Code-aware tokens: identifiers + their camelCase/snake_case subwords + symbols."""
    out: List[str] = []
    for m in _WORD.findall(text.lower() if False else text):
        if m.isalnum() or "_" in m:
            low = m.lower()
            out.append(low)
            parts = [p.lower() for p in _CAMEL.findall(m) if p]
            if len(parts) > 1:
                out.extend(parts)
            if "_" in m:
                out.extend(p for p in low.split("_") if p)
        else:
            out.append(m)   # keep symbols like ( = + . -> so operators carry signal
    return out


class HashingEmbedder:
    """Deterministic, offline, TF-weighted feature-hashing vectorizer."""

    def __init__(self, dim: int = 512) -> None:
        self.dim = int(dim)
        self.name = f"hashing:d{self.dim}"

    def _vec(self, text: str) -> np.ndarray:
        v = np.zeros(self.dim, dtype=np.float32)
        counts: dict = {}
        for tok in _tokens(text):
            counts[tok] = counts.get(tok, 0) + 1
        for tok, tf in counts.items():
            h = _stable_hash(tok)
            idx = h % self.dim
            sign = 1.0 if (h >> 63) & 1 else -1.0
            v[idx] += sign * (1.0 + np.log(tf))
        n = float(np.linalg.norm(v))
        return v / n if n > 0 else v

    def embed(self, texts: List[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        return np.vstack([self._vec(t) for t in texts]).astype(np.float32)

    def embed_query(self, text: str) -> np.ndarray:
        return self._vec(text)


class FastEmbedEmbedder:
    """Real semantic embeddings via fastembed (ONNX). Offline after model download."""

    def __init__(self, model: str, cache_dir: str) -> None:
        from fastembed import TextEmbedding  # raises if not installed → factory falls back
        import os
        os.makedirs(cache_dir, exist_ok=True)
        self._model = TextEmbedding(model_name=model, cache_dir=cache_dir)
        self.name = f"fastembed:{model}"
        # discover dim once
        probe = next(iter(self._model.embed(["x"])))
        self.dim = int(np.asarray(probe).shape[0])

    @staticmethod
    def _norm(a: np.ndarray) -> np.ndarray:
        n = np.linalg.norm(a, axis=1, keepdims=True)
        n[n == 0] = 1.0
        return (a / n).astype(np.float32)

    # bge truncates to ~512 tokens anyway; cap chars first so a pathological single long
    # line (minified JS / base64 / data blob) can't blow up tokenization/memory.
    _MAX_CHARS = 6000

    def embed(self, texts: List[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        clipped = [t[:self._MAX_CHARS] for t in texts]
        arr = np.asarray(list(self._model.embed(clipped)), dtype=np.float32)
        return self._norm(arr)

    def embed_query(self, text: str) -> np.ndarray:
        text = text[:self._MAX_CHARS]
        try:
            q = next(iter(self._model.query_embed([text])))
        except Exception:
            q = next(iter(self._model.embed([text])))
        q = np.asarray(q, dtype=np.float32)
        n = float(np.linalg.norm(q))
        return q / n if n > 0 else q


class CloudEmbedder:
    """Provider embedding model via LiteLLM. Requires an API key + embedding model."""

    def __init__(self, model: str) -> None:
        import litellm  # noqa: F401 (import guarded by factory)
        self._litellm = litellm
        prov = settings.llm_provider
        self.model = model if ("/" in model or prov == "openai") else f"{prov}/{model}"
        self.name = f"cloud:{self.model}"
        self.dim = int(np.asarray(self._raw([" "])[0]).shape[0])

    def _raw(self, texts: List[str]) -> List[list]:
        kwargs = {"model": self.model, "input": texts, "api_key": settings.llm_api_key}
        if settings.llm_api_base:
            kwargs["api_base"] = settings.llm_api_base
        resp = self._litellm.embedding(**kwargs)
        data = resp["data"] if isinstance(resp, dict) else resp.data
        return [d["embedding"] if isinstance(d, dict) else d.embedding for d in data]

    @staticmethod
    def _norm(a: np.ndarray) -> np.ndarray:
        n = np.linalg.norm(a, axis=1, keepdims=True)
        n[n == 0] = 1.0
        return (a / n).astype(np.float32)

    def embed(self, texts: List[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        return self._norm(np.asarray(self._raw(texts), dtype=np.float32))

    def embed_query(self, text: str) -> np.ndarray:
        return self.embed([text])[0]


# --------------------------------------------------------------------------- #
def _cfg(name: str, default):
    return getattr(settings, name, default)


def get_embedder(backend: Optional[str] = None) -> object:
    """Resolve an embedder. 'auto' = fastembed if available, else hashing (never silently
    cloud — that would surprise the user with cost/egress). Returns an object with
    .name/.dim/.embed()/.embed_query(); raises only for an explicit backend that can't load."""
    backend = (backend or _cfg("rag_embed_backend", "auto")).lower()
    model = _cfg("rag_embed_model", "BAAI/bge-small-en-v1.5")
    cache = _cfg("rag_fastembed_cache", "D:/Tools/fastembed_cache")
    dim = int(_cfg("rag_hashing_dim", 512))

    def _fastembed():
        return FastEmbedEmbedder(model, cache)

    if backend in ("fastembed", "local"):
        return _fastembed()
    if backend == "cloud":
        if settings.mock_mode:
            raise RuntimeError("cloud embeddings need an LLM_API_KEY")
        return CloudEmbedder(model if _cfg("rag_embed_model", None) else "text-embedding-3-small")
    if backend == "hashing":
        return HashingEmbedder(dim)
    # auto
    try:
        return _fastembed()
    except Exception:
        return HashingEmbedder(dim)


_SHARED: dict = {}


def shared_embedder(backend: Optional[str] = None):
    """Process-cached embedder keyed by backend, so the code index and the KB index reuse
    ONE loaded model instead of loading fastembed twice. Only successful loads are cached."""
    b = (backend or _cfg("rag_embed_backend", "auto")).lower()
    emb = _SHARED.get(b)
    if emb is None:
        emb = get_embedder(b)
        _SHARED[b] = emb
    return emb


def is_semantic(embedder) -> bool:
    """True when the active backend is neural (fastembed/cloud) vs the lexical hashing one."""
    return not getattr(embedder, "name", "").startswith("hashing")
