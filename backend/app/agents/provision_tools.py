"""Tools for the Provisioner agent (LLM-driven environment setup).

The Provisioner has the SAME autonomous read capabilities as the Hunter (it reads
ground truth directly — never depends on an upstream summary) PLUS execution tools
that run inside the persistent container. Read tools operate on the host workspace;
run/start/check operate inside the container via docker exec.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from .. import sandbox
from ..config import settings
from . import tools as read_tools

TOOL_SCHEMAS: List[dict] = [
    {"type": "function", "function": {
        "name": "list_files", "description": "列出项目目录结构（相对项目根），用于发现构建/配置文件。",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "read_file", "description": "读取任意项目文件（README/Dockerfile/compose/CI/Makefile/配置/迁移脚本等），可指定行。",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "search_code", "description": "正则检索项目文件，定位端口/入口/依赖/数据库配置等。",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"}, "max": {"type": "integer"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "detect_setup", "description": "返回项目的搭建线索：【应优先 read_file 的部署/搭建文档 docs_read_first（README / LAUNCH / INSTALL / DEPLOY / docs/ 等，通常直接写了怎么部署）】、存在哪些构建/配置文件、CI 工作流、检测到的框架与启动方式猜测。",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "run_command", "description": "在沙箱容器内执行 shell 命令（装依赖/迁移/建库/seed 等）。工作目录为项目根。返回 stdout/stderr/exit_code。",
        "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}}},
    {"type": "function", "function": {
        "name": "start_app", "description": "在容器内后台启动应用，并检测端口是否就绪。返回是否就绪与日志尾部。",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string", "description": "启动命令，如 'python app.py' 或 'python -m uvicorn main:app --host 127.0.0.1 --port 8000'"},
            "port": {"type": "integer"}}, "required": ["command", "port"]}}},
    {"type": "function", "function": {
        "name": "check_ready", "description": "检查应用在给定端口/路径是否已就绪（HTTP 可访问）。",
        "parameters": {"type": "object", "properties": {
            "port": {"type": "integer"}, "path": {"type": "string"}}, "required": ["port"]}}},
    {"type": "function", "function": {
        "name": "mark_ready", "description": "【应用已成功跑起来时调用】声明环境就绪，给出应用端口与可选的基础路径前缀。",
        "parameters": {"type": "object", "properties": {
            "port": {"type": "integer"}, "base_path": {"type": "string"}}, "required": ["port"]}}},
    {"type": "function", "function": {
        "name": "give_up", "description": "【确实无法在预算内搭建时调用】放弃搭建并说明原因（下游将回落逐候选轻量复现/静态结论）。",
        "parameters": {"type": "object", "properties": {"reason": {"type": "string"}}, "required": ["reason"]}}},
]

_SETUP_FILES = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "Dockerfile",
                "Makefile", "requirements.txt", "pyproject.toml", "setup.py", "package.json",
                "manage.py", "Procfile", ".env.example", ".env.sample", "README.md", "README.rst"]

# filename stems that usually contain deployment / setup instructions — read these FIRST
_DOC_HINTS = ("readme", "launch", "install", "deploy", "deployment", "setup", "getting_started",
              "getting-started", "gettingstarted", "quickstart", "quick_start", "usage",
              "docker", "run", "build", "development", "contributing", "hacking")


def _find_docs(root: Path) -> list:
    """Documentation files likely to explain how to deploy/set up the project (top-level
    README/LAUNCH/INSTALL/... + the docs/ directory), so the Provisioner reads them first."""
    docs: list = []
    try:
        for p in sorted(root.iterdir()):
            if p.is_file() and p.suffix.lower() in (".md", ".rst", ".txt", ""):
                if any(h in p.stem.lower() for h in _DOC_HINTS):
                    docs.append(p.name)
        d = root / "docs"
        if d.is_dir():
            for p in sorted(d.iterdir())[:20]:
                docs.append(f"docs/{p.name}")
    except Exception:
        pass
    return docs[:30]


def dispatch(env: dict, ctx, name: str, args: dict) -> dict:
    root: Path = ctx.root
    if name in ("list_files", "read_file", "search_code"):
        return read_tools.dispatch(ctx, name, args)

    if name == "detect_setup":
        present = [f for f in _SETUP_FILES if (root / f).exists()]
        ci_dir = root / ".github" / "workflows"
        ci = [p.name for p in ci_dir.glob("*.y*ml")] if ci_dir.exists() else []
        pys = sandbox._py_files(root)
        start = sandbox._derive_start(root, pys)
        return {"docs_read_first": _find_docs(root),   # 部署/搭建说明通常在这些文档里，先读它们
                "present": present, "ci_workflows": ci,
                "frameworks": sandbox._detect_frameworks(pys),
                "start_guess": {"command": start[0], "port": start[1]} if start else None}

    if name == "run_command":
        cmd = args.get("cmd", "")
        hist = env.setdefault("_cmds", {})
        hist[cmd] = hist.get(cmd, 0) + 1
        if hist[cmd] > 2:
            return {"note": "同一命令已多次执行且未奏效，请换一种方案（读配置/换命令/放弃）。", "exit_code": -1}
        cmd_timeout = ctx.state.get("budget", {}).get(
            "provisioner_cmd_timeout_sec", settings.provisioner_cmd_timeout_sec)
        return sandbox.exec_in(env, cmd, cmd_timeout)

    if name == "start_app":
        cmd, port = args.get("command", ""), int(args.get("port", 0))
        sandbox.exec_detached(env, cmd)
        env["port"] = port
        ready = False
        import time as _t
        for _ in range(30):
            if sandbox.check_ready(env, port)["up"]:
                ready = True
                break
            _t.sleep(0.5)
        log = sandbox.exec_in(env, "tail -c 500 /tmp/app.log", 20)["stdout"]
        return {"started": True, "ready": ready, "port": port, "log": log}

    if name == "check_ready":
        return sandbox.check_ready(env, int(args.get("port", env.get("port") or 0)),
                                   args.get("path", "/"))

    if name == "mark_ready":
        env["port"] = int(args.get("port", env.get("port") or 0))
        env["base_path"] = args.get("base_path", "") or ""
        env["ready"] = bool(sandbox.check_ready(env, env["port"])["up"])
        return {"ok": env["ready"], "note": ("环境就绪" if env["ready"] else "端口未响应，请先确认应用已启动")}

    if name == "give_up":
        env["gaveup"] = args.get("reason", "unspecified")
        return {"ok": True}

    return {"error": f"unknown tool {name}"}
