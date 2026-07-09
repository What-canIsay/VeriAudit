"""On-disk vector index with incremental (per-file-hash) updates.

Layout:  _data/rag/<project-hash>/{meta.json, vectors.npy, chunks.json}

Incremental: on (re)build we hash every source file; files whose content hash is unchanged
keep their existing rows, changed/new files are re-chunked + re-embedded, deleted files'
rows are dropped. The index is versioned by (index format, splitter version, embedder
name+dim) — any mismatch forces a full rebuild, so switching embedding backend or changing
the chunker never silently mixes incompatible vectors.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable, List, Optional

import numpy as np

from ..config import DATA_DIR, settings
from . import splitter
from .embeddings import get_embedder

INDEX_VERSION = "1.0"


def _index_dir(root: Path) -> Path:
    return DATA_DIR / "rag" / hashlib.md5(str(root).encode()).hexdigest()[:12]


class Index:
    def __init__(self, root: Path, embedder=None) -> None:
        self.root = Path(root)
        self.embedder = embedder or get_embedder()
        self.dir = _index_dir(self.root)
        self.dim = int(self.embedder.dim)
        self.vectors = np.zeros((0, self.dim), dtype=np.float32)
        self.chunks: List[dict] = []                 # aligned to vectors rows
        self.files: dict = {}                        # rel -> {"hash":..., "count":...}
        self.max_lines = int(getattr(settings, "rag_max_chunk_lines", 120))
        self.overlap = int(getattr(settings, "rag_chunk_overlap", 15))

    # ---- persistence ------------------------------------------------------- #
    def _compatible(self, meta: dict) -> bool:
        return (meta.get("index_version") == INDEX_VERSION
                and meta.get("splitter_version") == splitter.SPLITTER_VERSION
                and meta.get("embedder") == self.embedder.name
                and int(meta.get("dim", -1)) == self.dim)

    def load(self) -> bool:
        """Load an EXISTING compatible index. Returns False (→ empty, full rebuild) if none
        or incompatible."""
        mp = self.dir / "meta.json"
        if not mp.exists():
            return False
        try:
            meta = json.loads(mp.read_text(encoding="utf-8"))
            if not self._compatible(meta):
                return False
            self.vectors = np.load(self.dir / "vectors.npy")
            self.chunks = json.loads((self.dir / "chunks.json").read_text(encoding="utf-8"))
            self.files = meta.get("files", {})
            if self.vectors.shape[0] != len(self.chunks):   # corrupt → rebuild
                self.vectors = np.zeros((0, self.dim), dtype=np.float32)
                self.chunks = []
                self.files = {}
                return False
            return True
        except Exception:
            self.vectors = np.zeros((0, self.dim), dtype=np.float32)
            self.chunks = []
            self.files = {}
            return False

    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        np.save(self.dir / "vectors.npy", self.vectors)
        (self.dir / "chunks.json").write_text(json.dumps(self.chunks, ensure_ascii=False), encoding="utf-8")
        meta = {"index_version": INDEX_VERSION, "splitter_version": splitter.SPLITTER_VERSION,
                "embedder": self.embedder.name, "dim": self.dim,
                "files": self.files, "n_chunks": len(self.chunks)}
        (self.dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")

    # ---- build / incremental update --------------------------------------- #
    def build_or_update(self, batch: Optional[int] = None, progress: Optional[Callable] = None) -> dict:
        batch = int(batch or getattr(settings, "rag_embed_batch", 16))
        loaded = self.load()
        old_files = set(self.files)
        seen: set = set()
        new_chunks: List["splitter.CodeChunk"] = []
        changed: set = set()

        for rel, h, chunks in splitter.split_project(self.root, self.max_lines, self.overlap):
            seen.add(rel)
            prev = self.files.get(rel)
            if prev and prev.get("hash") == h:
                continue                                  # unchanged → keep existing rows
            changed.add(rel)
            self.files[rel] = {"hash": h, "count": len(chunks)}
            new_chunks.extend(chunks)

        deleted = old_files - seen
        drop = changed | deleted

        # drop rows belonging to changed/deleted files
        if drop and self.chunks:
            mask = np.array([c["file"] not in drop for c in self.chunks], dtype=bool)
            self.vectors = self.vectors[mask]
            self.chunks = [c for c, keep in zip(self.chunks, mask) if keep]
        for f in deleted:
            self.files.pop(f, None)

        # embed the new/changed chunks (batched) and append
        added = 0
        if new_chunks:
            parts = []
            for i in range(0, len(new_chunks), batch):
                b = new_chunks[i:i + batch]
                parts.append(self.embedder.embed([c.embed_text() for c in b]))
                if progress:
                    progress(min(i + batch, len(new_chunks)), len(new_chunks))
            V = np.vstack(parts).astype(np.float32)
            self.vectors = np.vstack([self.vectors, V]) if self.chunks else V
            for c in new_chunks:
                rec = c.to_meta()
                rec["preview"] = c.content[:1500]
                self.chunks.append(rec)
            added = len(new_chunks)

        self.save()
        return {"embedder": self.embedder.name, "dim": self.dim, "files": len(self.files),
                "chunks": len(self.chunks), "reindexed_files": len(changed),
                "deleted_files": len(deleted), "added_chunks": added,
                "incremental": bool(loaded)}

    # ---- search ------------------------------------------------------------ #
    def search_vectors(self, qvec: np.ndarray, k: int) -> List:
        """Top-k rows by cosine (vectors are L2-normalized ⇒ dot product). Returns
        (row_index, score); the retriever reranks with a lexical signal."""
        if self.vectors.shape[0] == 0:
            return []
        sims = self.vectors @ qvec.astype(np.float32)
        n = min(k, sims.shape[0])
        idx = np.argpartition(-sims, n - 1)[:n] if sims.shape[0] > n else np.arange(sims.shape[0])
        idx = idx[np.argsort(-sims[idx])]
        return [(int(i), float(sims[i])) for i in idx]
