"""Prepare a project's source into an isolated workspace directory.

Supports: git URL (shallow clone), uploaded ZIP, and local path (copy).
All target repo content is treated as UNTRUSTED (see docs/08).
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from .config import WORKSPACE_DIR

logger = logging.getLogger(__name__)

_ALLOWED_GIT_SCHEMES = {"http", "https"}
_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254"}
# build-output / VCS dirs we never need to audit (matches the old ignore_patterns set)
_IGNORE_NAMES = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


def _long(p) -> str:
    r"""Windows: return an extended-length (\\?\) path so file ops bypass the legacy
    260-char MAX_PATH limit. Real repos (e.g. gitea) nest deeply and carry long
    URL-encoded fixture filenames whose absolute path under our workspace dir exceeds
    260 chars, which otherwise makes copytree fail with ENOENT. No-op off Windows."""
    s = os.path.abspath(str(p))
    if os.name != "nt" or s.startswith("\\\\?\\"):
        return s
    if s.startswith("\\\\"):                       # UNC \\server\share → \\?\UNC\server\share
        return "\\\\?\\UNC\\" + s[2:]
    return "\\\\?\\" + s


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
        shutil.rmtree(_long(dest), ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        # core.longpaths lets git write files whose path exceeds Windows' 260-char MAX_PATH
        ["git", "-c", "core.longpaths=true", "clone", "--depth", "1", url, str(dest)],
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


def _copytree_resilient(src: str, dst: str, skipped: list) -> None:
    r"""Recursive copy that tolerates entries Windows can't read rather than aborting the
    whole tree (which shutil.copytree does on the first failure). The two real-world
    offenders on Windows:
      · WSL/Linux symlinks — reparse points with a Linux tag (e.g. curl's lib/.libs/*.la
        when the repo was built under WSL): os.path.islink() is False, but open()/stat()
        raise EINVAL / ERROR_CANT_ACCESS_FILE. Uncopyable by any Windows API.
      · paths past MAX_PATH — handled because src/dst arrive \\?\-prefixed.
    Un-copyable entries are skipped and recorded; everything readable still lands."""
    os.makedirs(dst, exist_ok=True)
    try:
        entries = list(os.scandir(src))
    except OSError as e:
        skipped.append((src, f"{type(e).__name__}: {e}"))
        return
    for e in entries:
        if e.name in _IGNORE_NAMES:
            continue
        s, d = os.path.join(src, e.name), os.path.join(dst, e.name)
        try:
            # follow_symlinks=False → a reparse point (incl. an unreadable WSL symlink) is
            # NOT reported as a directory and does NOT raise here; it falls through to
            # copy2 below, where the read failure is caught and the entry skipped.
            if e.is_dir(follow_symlinks=False):
                _copytree_resilient(s, d, skipped)
            else:
                shutil.copy2(s, d)
        except OSError as ex:
            skipped.append((s, f"{type(ex).__name__}: {ex.strerror or ex}"))


def prepare_local(project_id: str, src: str) -> Path:
    src_path = Path(src)
    if not src_path.exists():
        raise ValueError(f"Local path not found: {src}")
    dest = WORKSPACE_DIR / project_id
    if dest.exists():
        shutil.rmtree(_long(dest), ignore_errors=True)
    # \\?\ on both ends so deeply-nested/long-named files (gitea fixtures) copy without
    # tripping Windows MAX_PATH; resilient walk so WSL symlinks / special files that
    # Windows can't read (curl's lib/.libs) are skipped instead of failing the whole copy.
    skipped: list = []
    _copytree_resilient(_long(src_path), _long(dest), skipped)
    if skipped:
        logger.warning("prepare_local: skipped %d un-copyable entr%s under %s (e.g. WSL "
                       "symlinks / special files Windows can't read); first: %s",
                       len(skipped), "y" if len(skipped) == 1 else "ies", src, skipped[:3])
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
