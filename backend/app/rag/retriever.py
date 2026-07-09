"""Hybrid retriever: semantic (cosine over embeddings) + lexical (query/chunk token
overlap), reranked together. The lexical term keeps exact keyword hits (function names,
API calls) from being buried by a purely semantic match, and is what makes the lexical
`hashing` fallback still useful.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .embeddings import _tokens
from .indexer import Index


@dataclass
class RetrievalResult:
    chunk_id: str
    file: str
    lang: str
    chunk_type: str
    name: str
    start_line: int
    end_line: int
    score: float
    semantic_score: float
    lexical_score: float
    security_indicators: List[str]
    preview: str

    def to_dict(self, preview_lines: int = 40) -> dict:
        prev = "\n".join(self.preview.splitlines()[:preview_lines])
        return {"file": self.file, "start_line": self.start_line, "end_line": self.end_line,
                "name": self.name, "type": self.chunk_type,
                "score": round(self.score, 3), "semantic": round(self.semantic_score, 3),
                "lexical": round(self.lexical_score, 3),
                "security_indicators": self.security_indicators,
                "anchor": f"{self.file}:{self.start_line}", "preview": prev}


def _lexical_score(qtoks: set, chunk: dict) -> float:
    """Overlap of query tokens with the chunk's name + preview + indicators + path,
    normalized by the query size → [0,1]."""
    if not qtoks:
        return 0.0
    hay = " ".join([chunk.get("name", ""), chunk.get("file", ""),
                    " ".join(chunk.get("security_indicators", []) or []),
                    chunk.get("preview", "")])
    ctoks = set(_tokens(hay))
    if not ctoks:
        return 0.0
    return len(qtoks & ctoks) / len(qtoks)


def search(index: Index, query: str, k: int = 8, hybrid_alpha: float = 0.7) -> List[RetrievalResult]:
    if not query or not query.strip() or index.vectors.shape[0] == 0:
        return []
    qvec = index.embedder.embed_query(query)
    cand = index.search_vectors(qvec, max(k * 4, k + 10))   # over-fetch for lexical rerank
    qtoks = set(_tokens(query))
    out: List[RetrievalResult] = []
    for row, sem in cand:
        c = index.chunks[row]
        lex = _lexical_score(qtoks, c)
        score = hybrid_alpha * sem + (1.0 - hybrid_alpha) * lex
        out.append(RetrievalResult(
            chunk_id=c.get("chunk_id", ""), file=c["file"], lang=c.get("lang", ""),
            chunk_type=c.get("chunk_type", ""), name=c.get("name", ""),
            start_line=c.get("start_line", 0), end_line=c.get("end_line", 0),
            score=score, semantic_score=sem, lexical_score=lex,
            security_indicators=c.get("security_indicators", []) or [],
            preview=c.get("preview", "")))
    out.sort(key=lambda r: -r.score)
    return out[:k]
