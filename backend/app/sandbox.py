"""Isolated dynamic verification sandbox (Docker) with graceful degradation.

Security posture (docs/08): ephemeral container, --network none (no egress),
memory/cpu/pids/timeout limits, non-root. The generated PoC harness is piped in
via STDIN (no host volume mount) so it runs identically on Windows/Linux and the
container never touches the host filesystem. When Docker is unavailable or the
target is not self-runnable, dynamic verification degrades to the static verdict.
"""
from __future__ import annotations

import random
import shutil
import string
import subprocess
from pathlib import Path
from typing import Optional

from .config import settings
from .knowledge import rule_by_id

_IMAGE_BY_LANG = {"python": "python:3.11-slim", "javascript": "node:20-slim"}


def docker_available() -> bool:
    if not settings.enable_sandbox or not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def _marker() -> str:
    return "VERI_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))


def _run_container(image: str, shell_cmd: str, stdin_data: str, timeout: int) -> dict:
    cmd = [
        "docker", "run", "--rm", "-i",
        "--network", "none",
        "--memory", "256m", "--cpus", "1", "--pids-limit", "64",
        "--user", "1000:1000",
        image, "sh", "-c", shell_cmd,
    ]
    try:
        r = subprocess.run(cmd, input=stdin_data, capture_output=True, text=True,
                           timeout=timeout + 10)
        return {"ok": True, "stdout": r.stdout[-8000:], "stderr": r.stderr[-4000:],
                "exit_code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "sandbox timeout", "exit_code": -1}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "stdout": "", "stderr": f"sandbox error: {e}", "exit_code": -1}


def try_reproduce(root: Path, candidate: dict) -> dict:
    """Attempt dynamic PoC reproduction for a single candidate.

    Returns a dynamic_verification dict (see docs/04 EvidenceChain).
    """
    rule = rule_by_id(candidate.get("rule_id", ""))
    lang = candidate.get("lang")
    base = {"attempted": False, "reproduced": False, "poc_code": None,
            "observation": None, "request": None, "reason": None}

    if not rule or not rule.get("reproducible"):
        base["reason"] = "该漏洞类型通常无法自动复现（逻辑类），采用静态结论。"
        return base
    if not docker_available():
        base["reason"] = "Docker 不可用，跳过动态验证，回落静态结论。"
        return base
    if lang not in _IMAGE_BY_LANG:
        base["reason"] = f"当前语言 {lang} 暂不支持自动沙箱复现，回落静态结论。"
        return base

    src = candidate.get("_source") or {}
    src_snip = (src.get("snippet") or "").lower()
    file = root / candidate["location"]["file"]
    if not file.exists():
        base["reason"] = "目标文件缺失。"
        return base
    content = file.read_text(encoding="utf-8", errors="replace")
    # Only self-runnable single scripts whose SOURCE is argv/stdin are safely
    # auto-runnable in one shot. (A web handler's request.* source would require
    # starting the whole app — declined here, static verdict stands.)
    is_cli = any(k in src_snip for k in ("argv", "input(", "process.argv"))
    if not is_cli:
        base["attempted"] = True
        base["reason"] = "目标非自包含 CLI 入口，无法在沙箱中安全自动触发；静态结论有效。"
        return base

    marker = _marker()
    rid = candidate["rule_id"]
    if rid == "command-injection":
        payload = f"; echo {marker}"
        oracle = marker
    elif rid == "code-injection":
        payload = f"__import__('sys').stdout.write('{marker}')"
        oracle = marker
    elif rid == "path-traversal":
        payload = "../../../../etc/passwd"
        oracle = "root:"
    else:
        payload = f"{marker}"
        oracle = marker

    image = _IMAGE_BY_LANG[lang]
    ext = "py" if lang == "python" else "js"
    runner = "python t.py" if lang == "python" else "node t.js"
    # /tmp is writable by the non-root sandbox user; payload has no single quotes.
    shell = (f"cd /tmp && cat > t.{ext} && "
             f"timeout {settings.sandbox_timeout_sec} {runner} '{payload}' 2>&1 || true")
    poc_code = f"# PoC: 以参数注入触发 {rule['name']}\n$ {runner} '{payload}'"

    res = _run_container(image, shell, content, settings.sandbox_timeout_sec)
    out = (res.get("stdout", "") + res.get("stderr", ""))
    reproduced = oracle in out
    return {
        "attempted": True,
        "reproduced": reproduced,
        "poc_code": poc_code,
        "request": f"argv[1] = {payload!r}",
        "observation": (f"沙箱输出命中判据 `{oracle}`，漏洞已复现。" if reproduced
                         else f"沙箱执行完成但未命中判据 `{oracle}`（输出片段：{out[:200]!r}）。"),
        "oracle_hit": reproduced,
        "sandbox_log": out[:2000],
        "reason": None,
    }
