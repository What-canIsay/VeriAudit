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
        "name": "start_app", "description": "在容器内后台启动一个常驻服务（Web 应用或网络守护进程），并检测端口是否就绪。返回是否就绪与日志尾部。CLI/原生二进制这类【非常驻】目标不用它——直接用 run_target 跑。",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string", "description": "启动命令，如 'python app.py'、'python -m uvicorn main:app --host 127.0.0.1 --port 8000'、或守护进程 './src/openvpn/openvpn --config ... --management 127.0.0.1 1195'"},
            "port": {"type": "integer"},
            "kind": {"type": "string", "description": "http（Web 应用，默认）| network（非 HTTP 协议的网络守护进程，如 VPN 管理口/redis/自定义 TCP·UDP）"},
            "proto": {"type": "string", "description": "kind=network 时的协议：tcp（默认）| udp"}}, "required": ["command", "port"]}}},
    {"type": "function", "function": {
        "name": "check_ready", "description": "检查目标是否就绪。kind=http：HTTP 可访问；kind=network：TCP 能连上 / UDP 端口已绑定；kind=cli：用 smoke_cmd 试跑目标命令是否可执行。",
        "parameters": {"type": "object", "properties": {
            "port": {"type": "integer"}, "path": {"type": "string"},
            "kind": {"type": "string", "description": "http（默认）| network | cli"},
            "proto": {"type": "string", "description": "network 协议：tcp（默认）| udp"},
            "smoke_cmd": {"type": "string", "description": "kind=cli 时，用来验证目标可执行的一条命令（如 './src/openvpn/openvpn --version'）"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "net_send", "description": "向容器内 127.0.0.1:port 的【网络端口】发送一段自定义数据并读取响应——用于非 HTTP 协议的守护进程（VPN 管理口/redis/SMTP/自定义二进制协议）。payload 为要发送的文本（或 payload_b64 传原始字节的 base64），返回响应文本与字节数。用它确认守护进程真的起来并能交互。",
        "parameters": {"type": "object", "properties": {
            "port": {"type": "integer"}, "proto": {"type": "string", "description": "tcp（默认）| udp"},
            "payload": {"type": "string", "description": "要发送的文本（行协议记得带换行 \\n）"},
            "payload_b64": {"type": "string", "description": "要发送的原始字节的 base64（二进制协议用它，与 payload 二选一）"},
            "read_timeout": {"type": "number"}}, "required": ["port"]}}},
    {"type": "function", "function": {
        "name": "run_target", "description": "在容器内运行目标二进制/脚本/小型 harness，喂入自定义输入，返回【结构化崩溃证据】：退出码、终止信号（SIGSEGV/SIGABRT 等）、以及 AddressSanitizer/UBSan 报告。用于原生/CLI/库类目标（C/C++/Go/Rust 解析器等）的动态复现——崩溃或 sanitizer 报告即是内存安全/未定义行为漏洞的决定性证据。构建可复现时建议先用 -fsanitize=address,undefined -g 重编目标。",
        "parameters": {"type": "object", "properties": {
            "cmd": {"type": "string", "description": "运行目标的命令，如 './target @@' 或 './parser input.bin'（工作目录为项目根）"},
            "stdin": {"type": "string", "description": "从标准输入喂给目标的文本"},
            "stdin_b64": {"type": "string", "description": "从标准输入喂给目标的原始字节 base64（二进制输入用它）"},
            "input_files": {"type": "array", "description": "先落地的输入文件：[{path, content_b64}]，把构造好的畸形输入写到路径供 cmd 读取", "items": {"type": "object"}},
            "timeout": {"type": "integer"}}, "required": ["cmd"]}}},
    {"type": "function", "function": {
        "name": "mark_ready", "description": "【目标已成功跑起来/可交互时调用】声明环境就绪。kind=http 给端口(+可选 base_path)；kind=network 给端口+proto；kind=cli 给 target_cmd（后续核验会怎么运行目标，如 './target @@'）+可选 smoke_cmd。",
        "parameters": {"type": "object", "properties": {
            "port": {"type": "integer"}, "base_path": {"type": "string"},
            "kind": {"type": "string", "description": "http（默认）| network | cli"},
            "proto": {"type": "string", "description": "network 协议：tcp（默认）| udp"},
            "target_cmd": {"type": "string", "description": "kind=cli 时，后续核验运行目标的命令模板（如 './build/parser @@'，@@ 代表输入文件占位）"},
            "smoke_cmd": {"type": "string", "description": "kind=cli 时用来确认可执行的命令"},
            "build_note": {"type": "string", "description": "【给验证官的构建交接】源码树位置、当前二进制是否带 ASan/调试符号、以及复现建议（如：'超大型项目未整树重编，node 为 apt 预编译二进制无 ASan；请对可疑组件编最小 harness 叠 ASan，或用 gdb -batch 观察崩溃'）。会原样转达给验证官。"}}, "required": []}}},
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
        out = {"docs_read_first": _find_docs(root),   # 部署/搭建说明通常在这些文档里，先读它们
               "present": present, "ci_workflows": ci,
               "frameworks": sandbox._detect_frameworks(pys),
               "start_guess": {"command": start[0], "port": start[1]} if start else None}
        native = sandbox._native_scale(root)
        if native:   # C/C++ 目标：给出全量构建可行性判断，避免对超大项目盲目整树 ASan 重编
            out["native_build"] = native
        return out

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
        kind, proto = (args.get("kind") or "http"), (args.get("proto") or "tcp")
        sandbox.exec_detached(env, cmd)
        env["port"] = port
        ready = False
        import time as _t
        for _ in range(30):
            if sandbox.probe_ready(env, port, kind=kind, proto=proto)["up"]:
                ready = True
                break
            _t.sleep(0.5)
        log = sandbox.exec_in(env, "tail -c 500 /tmp/app.log", 20)["stdout"]
        return {"started": True, "ready": ready, "port": port, "kind": kind, "log": log}

    if name == "check_ready":
        return sandbox.probe_ready(env, int(args.get("port", env.get("port") or 0)),
                                   kind=(args.get("kind") or "http"),
                                   proto=(args.get("proto") or "tcp"),
                                   path=args.get("path", "/"), smoke_cmd=args.get("smoke_cmd", ""))

    if name == "net_send":
        payload_b64 = args.get("payload_b64") or ""
        if not payload_b64 and args.get("payload") is not None:
            import base64 as _b64
            payload_b64 = _b64.b64encode(str(args.get("payload")).encode("utf-8", "replace")).decode()
        return sandbox._net_interact(env, int(args.get("port", env.get("port") or 0)),
                                     proto=(args.get("proto") or "tcp"), payload_b64=payload_b64,
                                     read_timeout=float(args.get("read_timeout") or 5))

    if name == "run_target":
        stdin_b64 = args.get("stdin_b64") or ""
        if not stdin_b64 and args.get("stdin") is not None:
            import base64 as _b64
            stdin_b64 = _b64.b64encode(str(args.get("stdin")).encode("utf-8", "replace")).decode()
        return sandbox.run_target(env, args.get("cmd", ""), stdin_b64=stdin_b64,
                                  input_files=args.get("input_files") or [],
                                  timeout=args.get("timeout"))

    if name == "mark_ready":
        kind = (args.get("kind") or "http").lower()
        proto = (args.get("proto") or "tcp").lower()
        env["target_kind"] = kind
        env["proto"] = proto
        if "port" in args and args.get("port"):
            env["port"] = int(args.get("port"))
        env["base_path"] = args.get("base_path", "") or ""
        if kind == "cli":
            env["target_cmd"] = args.get("target_cmd", "") or ""
        if args.get("build_note"):
            env["build_note"] = str(args.get("build_note"))
        res = sandbox.probe_ready(env, env.get("port"), kind=kind, proto=proto,
                                  smoke_cmd=args.get("smoke_cmd", ""))
        env["ready"] = bool(res.get("up"))
        if env["ready"]:
            note = {"http": "环境就绪（HTTP 可访问）", "network": f"环境就绪（{proto} 端口可交互）",
                    "cli": "环境就绪（目标可执行，将以 run_target 逐个复现）"}[kind]
        else:
            note = {"http": "端口未响应 HTTP，请先确认应用已启动",
                    "network": f"{proto} 端口未就绪，请确认守护进程已监听该端口",
                    "cli": "目标命令不可执行（smoke_cmd 返回 127），请确认已构建"}[kind]
        return {"ok": env["ready"], "kind": kind, "note": note}

    if name == "give_up":
        env["gaveup"] = args.get("reason", "unspecified")
        return {"ok": True}

    return {"error": f"unknown tool {name}"}
