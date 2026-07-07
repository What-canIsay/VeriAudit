"""Prepare a project's source into an isolated workspace directory.

Supports: git URL (shallow clone), uploaded ZIP, and local path (copy).
All target repo content is treated as UNTRUSTED (see docs/08).
"""
from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from .config import WORKSPACE_DIR

_ALLOWED_GIT_SCHEMES = {"http", "https"}
_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254"}


def _safe_git_url(url: str) -> None:
    p = urlparse(url)
    if p.scheme not in _ALLOWED_GIT_SCHEMES:
        raise ValueError(f"Unsupported git scheme: {p.scheme!r} (only http/https)")
    host = (p.hostname or "").lower()
    if host in _BLOCKED_HOSTS or host.endswith(".internal"):
        raise ValueError("Blocked host for git clone (SSRF guard)")


def prepare_git(project_id: str, url: str) -> Path:
    _safe_git_url(url)
    dest = WORKSPACE_DIR / project_id
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        check=True, capture_output=True, timeout=300,
    )
    return dest


def prepare_zip(project_id: str, zip_path: Path) -> Path:
    dest = WORKSPACE_DIR / project_id
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            # zip-slip guard
            target = (dest / member).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise ValueError("Unsafe path in zip (zip-slip)")
        zf.extractall(dest)
    # collapse single top-level dir
    entries = [p for p in dest.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


def prepare_local(project_id: str, src: str) -> Path:
    src_path = Path(src)
    if not src_path.exists():
        raise ValueError(f"Local path not found: {src}")
    dest = WORKSPACE_DIR / project_id
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(src_path, dest, ignore=shutil.ignore_patterns(
        ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"))
    return dest


def head_commit(path: Path) -> Optional[str]:
    try:
        r = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return r.stdout.strip()[:12]
    except Exception:
        pass
    return None
