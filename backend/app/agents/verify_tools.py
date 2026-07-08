"""Tools for the agentic Validator (深度核验/复现).

The Validator gets the SAME autonomous read capability as the Hunter (read ground
truth, follow taint cross-file, inspect auth gates / sanitizers / DB schema) PLUS
dynamic tools that act against the ALREADY-RUNNING provisioned app so it can build a
PRECISE, project-specific PoC and actually trigger the vulnerability at runtime:

  read      : list_files / read_file / search_code / analyze_dataflow / search_vuln_kb
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
    {"type": "function", "function": {
        "name": "analyze_dataflow", "description": "对某处代码做 source→sink 污点追踪与可达性判定。",
        "parameters": {"type": "object", "properties": {
            "file": {"type": "string"}, "line": {"type": "integer"}}, "required": ["file", "line"]}}},
    {"type": "function", "function": {
        "name": "search_vuln_kb", "description": "检索漏洞知识库（成因/利用手法/修复范式）。",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string"}, "vuln_type": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "http_probe", "description": "向常驻应用发起一次 HTTP 请求（用于精确复现）。自动携带并保存 Cookie，可先登录再打受鉴权的接口。返回状态码、响应头、响应体、耗时。",
        "parameters": {"type": "object", "properties": {
            "method": {"type": "string", "description": "GET/POST/PUT/DELETE 等，默认 GET"},
            "path": {"type": "string", "description": "相对应用的路径，如 /backend/api/admin/delete_row.php?pk_name=..."},
            "headers": {"type": "object", "description": "额外请求头键值对（如 Content-Type、Authorization）"},
            "body": {"type": "string", "description": "请求体（POST 表单或 JSON 原文）"}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "run_command", "description": "在沙箱容器内执行 shell 命令。可用于专业工具与运行时调试：sqlmap（SQL注入确认/取数）、nuclei（配置/暴露类模板验证）、curl、strace（观察 open/execve 系统调用）、mysql 客户端（查/建/seed 数据）、tail 应用/错误日志等。返回 stdout/stderr/exit_code。",
        "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}}},
    {"type": "function", "function": {
        "name": "sql_log", "description": "白盒 SQL 观测：开启/读取 MySQL 通用查询日志，用于直接看到 payload 产生的真实 SQL（对盲注/二阶注入是决定性证据）。action=start 先开启并清空；发送 payload 后 action=read 读取新增日志。mysql_auth 可传认证参数如 '-uroot' 或 '-uroot -pXXee'。",
        "parameters": {"type": "object", "properties": {
            "action": {"type": "string", "description": "start | read | stop"},
            "mysql_auth": {"type": "string"}}, "required": ["action"]}}},
    {"type": "function", "function": {
        "name": "conclude", "description": "【核验完成时调用】给出最终结论：是否成立、是否已动态复现、依据、精确可运行的 PoC、修复建议。",
        "parameters": {"type": "object", "properties": {
            "verdict": {"type": "string", "description": "confirmed | suspected | rejected"},
            "reproduced": {"type": "boolean", "description": "是否在沙箱中真实触发/复现"},
            "confidence_reason": {"type": "string"},
            "poc": {"type": "string", "description": "精确、可复制运行的 PoC（完整请求含方法/路径/鉴权/参数/payload，或命令行）"},
            "remediation": {"type": "string"},
            "evidence": {"type": "string", "description": "关键证据摘要（如通用日志中的真实SQL、响应差异、strace 命中等）"},
            "setup_notes": {"type": "string", "description": "本次为完成复现所做的可复用搭建/鉴权准备（如：已创建的测试账号与密码、登录接口与会话获取方式、关键表结构），供后续漏洞核验复用，避免重复发现。"}},
            "required": ["verdict"]}}},
]


def _b64(s: str) -> str:
    return base64.b64encode((s or "").encode("utf-8", "replace")).decode("ascii")


def _curl_config(method: str, url: str, headers: dict, body: str) -> str:
    """Build a curl config file (-K) so arbitrary payloads/quotes never touch the shell."""
    def esc(v: str) -> str:
        return str(v).replace("\\", "\\\\").replace('"', '\\"')
    lines = [f'url = "{esc(url)}"', f'request = "{esc(method or "GET")}"']
    for k, v in (headers or {}).items():
        lines.append(f'header = "{esc(k)}: {esc(v)}"')
    if body:
        lines.append(f'data = "{esc(body)}"')
    return "\n".join(lines) + "\n"


def _http_probe(env: dict, method: str, path: str, headers: dict, body: str) -> dict:
    port = env.get("port")
    if not port:
        return {"error": "应用端口未知（环境未就绪？）"}
    base = env.get("base_path", "") or ""
    url = f"http://127.0.0.1:{port}{base}{path}"
    cfg = _curl_config(method, url, headers, body)
    marker = "__CODE__"
    # write config via base64 (no shell-escaping of payloads), keep a shared cookie jar
    cmd = (f"echo {_b64(cfg)} | base64 -d > /tmp/vcfg && "
           f"curl -s -i -m 20 -c /tmp/vjar -b /tmp/vjar -K /tmp/vcfg "
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


def dispatch(env: dict, ctx, name: str, args: dict, sink: dict) -> dict:
    if name in ("list_files", "read_file", "search_code", "analyze_dataflow", "search_vuln_kb"):
        return read_tools.dispatch(ctx, name, args)

    if name == "http_probe":
        return _http_probe(env, args.get("method", "GET"), args.get("path", ""),
                           args.get("headers") or {}, args.get("body", ""))

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

    if name == "conclude":
        return {"ok": True}   # captured by the caller's on_tool

    return {"error": f"unknown tool {name}"}
