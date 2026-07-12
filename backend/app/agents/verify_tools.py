"""Tools for the agentic Validator (深度核验/复现).

The Validator gets the SAME autonomous read capability as the Hunter (read ground
truth, follow taint cross-file, inspect auth gates / sanitizers / DB schema) PLUS
dynamic tools that act against the ALREADY-RUNNING provisioned app so it can build a
PRECISE, project-specific PoC and actually trigger the vulnerability at runtime:

  read      : list_files / read_file / search_code / check_reachability / cg_* / search_vuln_kb
  exploit   : http_probe   (fire a crafted request at the standing app; keeps a cookie
                            jar so multi-step auth flows work)
  runtime   : run_command  (shell in the container — sqlmap / nuclei / curl / strace /
                            mysql client / read app+error logs …)
  white-box : sql_log      (enable + read MySQL general query log → observe the ACTUAL
                            SQL the payload produced; definitive for blind/2nd-order SQLi)
  commit    : conclude     (final verdict + reproduced? + precise PoC + remediation)

Read tools operate on the host workspace; exploit/runtime/white-box operate inside the
persistent provisioning container via docker exec. Everything stays in the sandbox.
"""
from __future__ import annotations

import base64
import json
from typing import List

from .. import sandbox
from ..config import settings
from . import tools as read_tools

TOOL_SCHEMAS: List[dict] = [
    {"type": "function", "function": {
        "name": "list_files", "description": "列出项目目录结构（相对项目根），用于定位相关文件。",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "read_file", "description": "阅读任意项目源码（可指定起止行）。核验漏洞时应读全上下文：污点源头、入口路由、鉴权中间件、被调用的净化 helper、DB schema 等，不要只看 sink 片段。",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "search_code", "description": "正则全局检索代码，定位污点源/路由注册/鉴权/净化函数定义等。",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"}, "max": {"type": "integer"}}, "required": ["pattern"]}}},
    *read_tools.CALLGRAPH_TOOL_SCHEMAS,   # identical to the Hunter's — shared, no drift
    {"type": "function", "function": {
        "name": "search_code_semantic", "description": (
            "语义/关键词混合检索整项目代码，用自然语言按【含义】定位跨文件上下文（如'该 sink 的净化函数定义'、"
            "'同类危险调用的其它位置'、'校验此会话/权限的中间件'、'该输入的其它使用点'）。核验时用它省去逐个 grep 猜函数名。\n"
            "· 局限：命中≠有漏洞、没召回≠安全；嵌入降级为词法时召回更弱。\n"
            "· 【铁律·防误报】它只是定位线索，【最终 conclude 的判定必须基于 read_file 对确切代码 + 运行时证据】，"
            "绝不能仅凭语义检索命中或未命中下结论。已知确切符号时用 search_code。"),
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string"}, "k": {"type": "integer"}}, "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "search_vuln_kb", "description": "检索内置【漏洞知识库】（成因/利用手法/修复范式/PoC 提示），【语义+关键词混合】匹配。这是通用漏洞知识，非本项目代码；找项目代码用 search_code / search_code_semantic。",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string"}, "vuln_type": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "http_probe", "description": "向常驻应用发起一次 HTTP 请求（用于精确复现）。按 session 选择对应角色的 Cookie 罐（自动携带并保存），可先登录再打受鉴权的接口。返回状态码、响应头、响应体、耗时。",
        "parameters": {"type": "object", "properties": {
            "method": {"type": "string", "description": "GET/POST/PUT/DELETE 等，默认 GET"},
            "path": {"type": "string", "description": "相对应用的路径，如 /backend/api/admin/delete_row.php?pk_name=..."},
            "headers": {"type": "object", "description": "额外请求头键值对（如 Content-Type、Authorization）"},
            "body": {"type": "string", "description": "请求体（POST 表单或 JSON 原文）"},
            "session": {"type": "string", "description": "会话/角色名（如 admin、user）；复用预热阶段建立的登录态。留空=匿名会话。"}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "run_command", "description": "在沙箱容器内执行 shell 命令。可用于专业工具与运行时调试：sqlmap（SQL注入确认/取数）、nuclei（配置/暴露类模板验证）、curl、strace（观察 open/execve 系统调用）、gdb（batch 非交互模式定位原生崩溃的精确栈帧/寄存器/内存，如 `gdb -batch -ex run -ex bt --args ./目标 输入`，或 `gdb -batch -p PID ...` 附加常驻守护进程）、mysql 客户端（查/建/seed 数据）、tail 应用/错误日志等。返回 stdout/stderr/exit_code。",
        "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}}},
    {"type": "function", "function": {
        "name": "sql_log", "description": "白盒 SQL 观测：开启/读取 MySQL 通用查询日志，用于直接看到 payload 产生的真实 SQL（对盲注/二阶注入是决定性证据）。action=start 先开启并清空；发送 payload 后 action=read 读取新增日志。mysql_auth 可传认证参数如 '-uroot' 或 '-uroot -pXXee'。",
        "parameters": {"type": "object", "properties": {
            "action": {"type": "string", "description": "start | read | stop"},
            "mysql_auth": {"type": "string"}}, "required": ["action"]}}},
    {"type": "function", "function": {
        "name": "net_send", "description": "【非 HTTP 网络协议复现】向常驻守护进程的 127.0.0.1:port 发送自定义数据并读响应——用于 VPN 管理口/redis/SMTP/自定义 TCP·UDP 协议（http_probe 只能打 HTTP）。payload 传文本（行协议记得带 \\n），或 payload_b64 传原始字节 base64。构造畸形/越权/注入报文，据响应或行为判定漏洞。",
        "parameters": {"type": "object", "properties": {
            "port": {"type": "integer"}, "proto": {"type": "string", "description": "tcp（默认）| udp"},
            "payload": {"type": "string"}, "payload_b64": {"type": "string"},
            "read_timeout": {"type": "number"}}, "required": ["port"]}}},
    {"type": "function", "function": {
        "name": "run_target", "description": "【原生/CLI/库类目标的实弹复现】在容器内以自定义输入运行目标二进制或小型 harness，返回结构化崩溃证据：退出码、终止信号（SIGSEGV/SIGABRT/SIGFPE…）、AddressSanitizer/UBSan 报告。对内存安全/未定义行为类漏洞——【触发崩溃或 sanitizer 报告即为决定性动态复现证据】。强烈建议先用 run_command 以 -fsanitize=address,undefined -g 重编目标（或编一个只调用可疑函数的小 harness），再喂构造好的畸形输入。输入可经 stdin/stdin_b64 或 input_files([{path,content_b64}]) 落地。",
        "parameters": {"type": "object", "properties": {
            "cmd": {"type": "string", "description": "运行目标的命令，如 './target crash.bin' 或 './harness'"},
            "stdin": {"type": "string"}, "stdin_b64": {"type": "string"},
            "input_files": {"type": "array", "items": {"type": "object"},
                            "description": "先落地的输入文件：[{path, content_b64}]"},
            "timeout": {"type": "integer"}}, "required": ["cmd"]}}},
    {"type": "function", "function": {
        "name": "report_incidental", "description": "【核验期间顺带发现一个与当前候选无关的新漏洞时调用】把它登记回候选池，供后续独立验证（不要用它给当前候选下结论——当前候选用 conclude）。发现即报，宁多勿漏，下游有独立验证。",
        "parameters": {"type": "object", "properties": {
            "vuln_type": {"type": "string", "description": "如 'CWE-89 SQL Injection'"},
            "file": {"type": "string"}, "line": {"type": "integer"},
            "confidence": {"type": "number"}, "rationale": {"type": "string"}},
            "required": ["vuln_type", "file", "line", "rationale"]}}},
    {"type": "function", "function": {
        "name": "conclude", "description": "【核验完成时调用】给出最终结论：是否成立、是否已动态复现、依据、精确可运行的 PoC、修复建议。",
        "parameters": {"type": "object", "properties": {
            "verdict": {"type": "string", "description": "confirmed | suspected | rejected"},
            "reproduced": {"type": "boolean", "description": "是否在沙箱中真实触发/复现"},
            "cvss_vector": {"type": "string", "description": "针对本漏洞【具体情况】的 CVSS v3.1 向量，形如 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N。请从该漏洞类别的基准出发，按你在核验中掌握的真实情况逐项调整：需登录才能触发→PR:L/H；仅内网/需本地→AV:A/L/P；需诱导用户点击→UI:R；能越权影响其他用户/组件→S:C；据实际能读取/篡改/破坏的程度定 C/I/A。仅在 verdict=confirmed/suspected 时给出。"},
            "confidence_reason": {"type": "string"},
            "poc": {"type": "string", "description": "精确、可复制运行的 PoC（完整请求含方法/路径/鉴权/参数/payload，或命令行）"},
            "remediation": {"type": "string"},
            "evidence": {"type": "string", "description": "关键证据摘要（如通用日志中的真实SQL、响应差异、strace 命中等）"},
            "setup_notes": {"type": "string", "description": "本次为完成复现所做的可复用搭建/鉴权准备（如：已创建的测试账号与密码、登录接口与会话获取方式、关键表结构），供后续漏洞核验复用，避免重复发现。"}},
            "required": ["verdict"]}}},
]

# Preheat toolset (Provisioner): same dynamic tools MINUS conclude, PLUS preheat_ready.
_PREHEAT_READY = {"type": "function", "function": {
    "name": "preheat_ready", "description": "【预热完成时调用】登记本项目为漏洞核验准备好的可复用基底：备忘（测试账号/登录配方/关键表结构）与角色→会话映射。若本项目无需鉴权/准备，也调用它并说明。",
    "parameters": {"type": "object", "properties": {
        "memo": {"type": "string", "description": "可复用备忘：已创建的测试账号与密码、登录接口/方式、关键表结构、注意事项。"},
        "sessions": {"type": "object", "description": "角色→会话名映射，如 {\"admin\":\"admin\",\"user\":\"user\"}；这些会话的登录态已保存在对应 Cookie 罐中。"}},
        "required": ["memo"]}}}

PREHEAT_SCHEMAS: List[dict] = [t for t in TOOL_SCHEMAS
                              if t["function"]["name"] != "conclude"] + [_PREHEAT_READY]

# tools disabled wholesale when their subsystem is off (ENABLE_RAG). search_vuln_kb stays
# (it degrades to keyword-only internally); only the code semantic search is hidden.
_RAG_GATED = {"search_code_semantic"}


def _gate(schemas: List[dict]) -> List[dict]:
    if getattr(settings, "enable_rag", True):
        return schemas
    return [t for t in schemas if t["function"]["name"] not in _RAG_GATED]


def active_schemas() -> List[dict]:
    """Validator toolset with RAG-gated tools removed when ENABLE_RAG=false."""
    return _gate(TOOL_SCHEMAS)


def active_preheat_schemas() -> List[dict]:
    return _gate(PREHEAT_SCHEMAS)


def _b64(s: str) -> str:
    return base64.b64encode((s or "").encode("utf-8", "replace")).decode("ascii")


def _as_headers(h) -> dict:
    """Coerce a model-supplied `headers` value into a dict. The LLM sometimes passes a JSON
    string, a "Key: Value" block, or a list instead of an object — tolerate all of these so a
    single malformed tool argument can never crash the verification phase."""
    if isinstance(h, dict):
        return h
    if isinstance(h, str):
        s = h.strip()
        if not s:
            return {}
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
        out = {}
        for line in s.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                out[k.strip()] = v.strip()
        return out
    if isinstance(h, (list, tuple)):
        out = {}
        for item in h:
            if isinstance(item, str) and ":" in item:
                k, v = item.split(":", 1)
                out[k.strip()] = v.strip()
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                out[str(item[0])] = str(item[1])
        return out
    return {}


def _curl_config(method: str, url: str, headers, body: str) -> str:
    """Build a curl config file (-K) so arbitrary payloads/quotes never touch the shell."""
    def esc(v: str) -> str:
        return str(v).replace("\\", "\\\\").replace('"', '\\"')
    lines = [f'url = "{esc(url)}"', f'request = "{esc(method or "GET")}"']
    for k, v in _as_headers(headers).items():
        lines.append(f'header = "{esc(k)}: {esc(v)}"')
    if body:
        lines.append(f'data = "{esc(body)}"')
    return "\n".join(lines) + "\n"


def _jar(session: str) -> str:
    s = "".join(ch for ch in (session or "") if ch.isalnum() or ch in "_-")[:24]
    return f"/tmp/vjar_{s}" if s else "/tmp/vjar"


def _http_probe(env: dict, method: str, path: str, headers: dict, body: str,
                session: str = "") -> dict:
    port = env.get("port")
    if not port:
        return {"error": "应用端口未知（环境未就绪？）"}
    base = env.get("base_path", "") or ""
    url = f"http://127.0.0.1:{port}{base}{path}"
    cfg = _curl_config(method, url, headers, body)
    marker = "__CODE__"
    jar = _jar(session)
    # write config via base64 (no shell-escaping of payloads); cookie jar per role/session
    cmd = (f"echo {_b64(cfg)} | base64 -d > /tmp/vcfg && "
           f"curl -s -i -m 20 -c {jar} -b {jar} -K /tmp/vcfg "
           f"-w '\\n{marker}%{{http_code}} TIME:%{{time_total}}'")
    r = sandbox.exec_in(env, cmd, 40)
    out = r.get("stdout", "") or ""
    code = ""
    if marker in out:
        out, _, tail = out.rpartition(marker)
        code = tail.strip()
    return {"request": f"{method or 'GET'} {url}", "status": code,
            "response": out[-4000:], "stderr": (r.get("stderr") or "")[-500:]}


def _sql_log(env: dict, action: str, auth: str) -> dict:
    auth = auth or "-uroot"
    if action == "start":
        sandbox.exec_in(env, ": > /tmp/vsql.log 2>/dev/null; chmod 666 /tmp/vsql.log 2>/dev/null || true", 20)
        r = sandbox.exec_in(env, f"mysql {auth} -N -e \"SET GLOBAL log_output='FILE'; "
                                 f"SET GLOBAL general_log_file='/tmp/vsql.log'; SET GLOBAL general_log=1;\"", 30)
        ok = r.get("exit_code") == 0
        return {"ok": ok, "note": "通用日志已开启并清空" if ok else "开启失败，请检查 mysql 认证参数",
                "stderr": (r.get("stderr") or "")[-400:]}
    if action == "read":
        r = sandbox.exec_in(env, "tail -c 4000 /tmp/vsql.log 2>/dev/null", 20)
        return {"log": r.get("stdout", ""), "stderr": (r.get("stderr") or "")[-300:]}
    if action == "stop":
        sandbox.exec_in(env, f"mysql {auth} -N -e 'SET GLOBAL general_log=0;'", 20)
        return {"ok": True}
    return {"error": "action 必须是 start|read|stop"}


def dispatch(env: dict, ctx, name: str, args: dict, sink: dict = None) -> dict:
    if name in ("list_files", "read_file", "search_code", "check_reachability", "search_vuln_kb",
                "search_code_semantic", "cg_overview", "cg_callers", "cg_callees", "cg_path",
                "cg_subgraph", "cg_dataflow"):
        return read_tools.dispatch(ctx, name, args)

    if name == "http_probe":
        return _http_probe(env, args.get("method", "GET"), args.get("path", ""),
                           args.get("headers") or {}, args.get("body", ""), args.get("session", ""))

    if name == "run_command":
        cmd = args.get("cmd", "")
        hist = env.setdefault("_vcmds", {})
        hist[cmd] = hist.get(cmd, 0) + 1
        if hist[cmd] > 2:
            return {"note": "同一命令已多次执行且未奏效，请换一种方案或据现有证据下结论。", "exit_code": -1}
        cmd_timeout = ctx.state.get("budget", {}).get(
            "provisioner_cmd_timeout_sec", settings.provisioner_cmd_timeout_sec)
        return sandbox.exec_in(env, cmd, cmd_timeout)

    if name == "sql_log":
        return _sql_log(env, args.get("action", ""), args.get("mysql_auth", ""))

    if name == "net_send":
        if not env or not env.get("container"):
            return {"error": "无常驻容器（环境未就绪？）"}
        payload_b64 = args.get("payload_b64") or ""
        if not payload_b64 and args.get("payload") is not None:
            payload_b64 = base64.b64encode(str(args.get("payload")).encode("utf-8", "replace")).decode()
        return sandbox._net_interact(env, int(args.get("port", env.get("port") or 0)),
                                     proto=(args.get("proto") or "tcp"), payload_b64=payload_b64,
                                     read_timeout=float(args.get("read_timeout") or 5))

    if name == "run_target":
        if not env or not env.get("container"):
            return {"error": "无常驻容器（环境未就绪？）"}
        stdin_b64 = args.get("stdin_b64") or ""
        if not stdin_b64 and args.get("stdin") is not None:
            stdin_b64 = base64.b64encode(str(args.get("stdin")).encode("utf-8", "replace")).decode()
        return sandbox.run_target(env, args.get("cmd", ""), stdin_b64=stdin_b64,
                                  input_files=args.get("input_files") or [], timeout=args.get("timeout"))

    if name == "report_incidental":
        return read_tools.record_incidental(ctx, args)

    if name in ("conclude", "preheat_ready"):
        return {"ok": True}   # captured by the caller's on_tool

    return {"error": f"unknown tool {name}"}
