"""Isolated dynamic verification sandbox (Docker) — general open-source compatible.

Reproduction strategies (auto-selected per candidate):
  1. Web-app path — for web-route vulns (source = request.*): the target application
     is booted inside a container and a crafted HTTP request is fired at the vulnerable
     route+param. To support ARBITRARY open-source projects it: (a) installs the project's
     own dependencies (detected frameworks + requirements.txt / pyproject / setup.py),
     (b) auto-detects the start command (Flask / FastAPI / Django), (c) creates the base
     directories referenced at the sink. Covers the majority of real web vulns
     (command injection / path traversal / XSS / SSTI).
  2. CLI path — for self-contained scripts whose source is argv/stdin.

Disk/security notes:
  - Reuses the already-present `python:3.11-slim` base plus a tiny curl layer (no heavy
    framework prebake); project deps install into the ephemeral `--rm` container and are
    freed after each run — no disk accumulation. Images are never auto-pulled.
  - The repro container is ephemeral, resource-capped, cap-drop ALL + no-new-privileges,
    no host mount (workspace streamed as a tar over STDIN). It is granted network ONLY so
    projects can install their dependencies (set VERIAUDIT_SANDBOX_ALLOW_NETWORK=false for
    strict no-egress). Anything that can't be safely auto-triggered degrades to static.
"""
from __future__ import annotations

import io
import random
import re
import string
import subprocess
import tarfile
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import quote

from . import analysis
from .config import settings
from .knowledge import rule_by_id

_BASE_IMAGE = "python:3.11-slim"
_CLI_IMAGE = {"python": "python:3.11-slim", "javascript": "node:20-slim"}
_WEB_IMAGE_TAG = f"{settings.sandbox_image_prefix}-web"
_SKIP_TAR = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".idea"}

_WEB_DOCKERFILE = (
    "FROM python:3.11-slim\n"
    "RUN apt-get update && apt-get install -y --no-install-recommends curl "
    "&& rm -rf /var/lib/apt/lists/*\n"
)


def _marker() -> str:
    return "VERI" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))


def _docker(*args, timeout=30, **kw):
    return subprocess.run(["docker", *args], capture_output=True, timeout=timeout, **kw)


def docker_available() -> bool:
    import shutil
    if not settings.enable_sandbox or not shutil.which("docker"):
        return False
    try:
        return _docker("info", timeout=15).returncode == 0
    except Exception:
        return False


def _image_present(img: str) -> bool:
    try:
        return _docker("image", "inspect", img, timeout=15).returncode == 0
    except Exception:
        return False


def _ensure_web_image() -> Optional[str]:
    """Build a tiny `python:3.11-slim + curl` image once. Never pulls new base images
    (the slim base must already be present) so C: drive stays flat."""
    if _image_present(_WEB_IMAGE_TAG):
        return _WEB_IMAGE_TAG
    if not _image_present(_BASE_IMAGE):
        return None  # don't auto-pull
    try:
        b = subprocess.run(["docker", "build", "-t", _WEB_IMAGE_TAG, "-"],
                           input=_WEB_DOCKERFILE.encode(), capture_output=True, timeout=180)
        return _WEB_IMAGE_TAG if b.returncode == 0 else None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
def try_reproduce(root: Path, candidate: dict) -> dict:
    rule = rule_by_id(candidate.get("rule_id", ""))
    base = {"attempted": False, "reproduced": False, "poc_code": None,
            "observation": None, "request": None, "reason": None}

    if not rule or not rule.get("reproducible"):
        base["reason"] = "该漏洞类型通常无法自动复现（逻辑类），采用静态结论。"
        return base
    if not docker_available():
        base["reason"] = "Docker 不可用，跳过动态验证，回落静态结论。"
        return base
    file = root / candidate["location"]["file"]
    if not file.exists():
        base["reason"] = "目标文件缺失。"
        return base
    lang = candidate.get("lang")
    if lang in (None, "unknown"):
        lang = {".py": "python", ".js": "javascript", ".ts": "javascript"}.get(file.suffix.lower())

    probe = _derive_web_probe(root, candidate, rule, lang)
    if probe:
        return _run_web(root, probe, rule)

    src_snip = ((candidate.get("_source") or {}).get("snippet") or "").lower()
    if lang in _CLI_IMAGE and any(k in src_snip for k in ("argv", "input(", "process.argv")):
        return _run_cli(root, candidate, rule, lang)

    base["attempted"] = True
    base["reason"] = "无法为该目标自动构造可复现探针（非 CLI 入口且未能推导 Web 路由/启动方式）；静态结论有效。"
    return base


# --------------------------------------------------------------------------- #
# Web-app reproduction (general)
# --------------------------------------------------------------------------- #
def _payload_for(rid: str) -> Tuple[Optional[str], Optional[str]]:
    m = _marker()
    if rid == "command-injection":
        return f";echo {m}", m
    if rid == "path-traversal":
        return "../../../../../../etc/passwd", "root:"
    if rid == "xss":
        return f"<x>{m}</x>", m
    if rid == "ssti":
        return "{{7*7}}", "49"
    return None, None


def _py_files(root: Path) -> List[Tuple[str, str]]:
    out = []
    for p, lang in analysis.iter_source_files(root):
        if lang == "python":
            out.append((analysis._rel(root, p), analysis.read_text(p)))
    return out


def _detect_frameworks(pys: List[Tuple[str, str]]) -> List[str]:
    fw = set()
    for _rel, txt in pys:
        if re.search(r"(from|import)\s+flask", txt):
            fw.add("flask")
        if re.search(r"\bfastapi\b", txt, re.I):
            fw.update(["fastapi", "uvicorn"])
        if re.search(r"(from|import)\s+django", txt):
            fw.add("django")
        if re.search(r"(from|import)\s+bottle", txt):
            fw.add("bottle")
        if "jinja2" in txt:
            fw.add("jinja2")
        if re.search(r"(from|import)\s+aiohttp", txt):
            fw.add("aiohttp")
    return sorted(fw)


def _derive_start(root: Path, pys: List[Tuple[str, str]]) -> Optional[Tuple[str, int]]:
    if (root / "manage.py").exists():
        return ("python manage.py runserver 127.0.0.1:8000 --noreload", 8000)
    for rel, txt in pys:
        if re.search(r"\.run\(", txt) and ("Flask(" in txt or "flask" in txt.lower()):
            m = re.search(r"\.run\([^)]*port\s*=\s*(\d+)", txt)
            return (f"python '{rel}'", int(m.group(1)) if m else 5000)
    for rel, txt in pys:
        m = re.search(r"(\w+)\s*=\s*FastAPI\(", txt)
        if m:
            mod = rel[:-3].replace("/", ".").replace("\\", ".")
            return (f"python -m uvicorn {mod}:{m.group(1)} --host 127.0.0.1 --port 8000", 8000)
    for rel, txt in pys:
        if re.search(r"if\s+__name__\s*==", txt) and re.search(
                r"(from|import)\s+(flask|fastapi|bottle|aiohttp|tornado)", txt, re.I):
            return (f"python '{rel}'", 5000)
    return None


def _find_route(lines, sink_line: int) -> Optional[Tuple[str, int]]:
    for j in range(min(sink_line - 1, len(lines) - 1), -1, -1):
        m = re.search(r"@\w+\.(?:route|get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", lines[j])
        if m:
            return m.group(1), j
    return None


def _find_param(lines, start: int, end: int) -> Optional[str]:
    for i in range(max(0, start), min(end + 2, len(lines))):
        m = re.search(r"request\.(?:args|values|form|json|GET|POST|cookies|headers)"
                      r"(?:\.get\(\s*|\[\s*)['\"]([^'\"]+)['\"]", lines[i])
        if m:
            return m.group(1)
    return None


def _base_dirs(sink_text: str) -> List[str]:
    dirs = []
    for m in re.finditer(r"['\"](/[A-Za-z0-9_./-]+/)['\"]", sink_text):
        dirs.append(m.group(1))
    return dirs


def _derive_web_probe(root: Path, candidate: dict, rule: dict, lang) -> Optional[dict]:
    if lang != "python":
        return None
    payload, oracle = _payload_for(rule["id"])
    if not payload:
        return None
    rel = candidate["location"]["file"]
    lines = analysis.read_text(root / rel).splitlines() if (root / rel).exists() else []
    if not lines:
        return None
    sink_line = candidate["location"]["line"]
    route_info = _find_route(lines, sink_line)
    if not route_info:
        return None
    route, route_line = route_info
    param = _find_param(lines, route_line, sink_line)
    if not param:
        return None
    pys = _py_files(root)
    start = _derive_start(root, pys)
    if not start:
        return None
    sink_text = lines[sink_line - 1] if 0 < sink_line <= len(lines) else ""
    return {
        "start": start[0], "port": start[1],
        "path": f"{route}?{param}={quote(payload, safe='')}",
        "oracle": oracle, "route": route, "param": param,
        "frameworks": _detect_frameworks(pys),
        "base_dirs": _base_dirs(sink_text),
    }


def _tar_workspace(root: Path) -> bytes:
    buf = io.BytesIO()

    def _filter(ti: "tarfile.TarInfo"):
        if any(seg in _SKIP_TAR for seg in ti.name.split("/")):
            return None
        if ti.size > 3_000_000:
            return None
        return ti

    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.add(str(root), arcname="app", filter=_filter)
    return buf.getvalue()


def _run_web(root: Path, probe: dict, rule: dict) -> dict:
    image = _ensure_web_image()
    if not image:
        return {"attempted": True, "reproduced": False, "poc_code": None, "request": None,
                "observation": None, "reason": "沙箱镜像不可用（基础镜像缺失或构建失败），回落静态结论。"}

    port, path, oracle, start = probe["port"], probe["path"], probe["oracle"], probe["start"]
    fw = " ".join(probe.get("frameworks") or [])
    mkdirs = " ".join(["/var/data", "/data", "/uploads", "./data", "./uploads",
                       *(probe.get("base_dirs") or [])])
    install = (
        (f"pip install -q {fw} 2>&1 | tail -2 ; " if fw else "")
        + "[ -f requirements.txt ] && pip install -q -r requirements.txt 2>&1 | tail -3 ; "
        "([ -f setup.py ] || [ -f pyproject.toml ]) && pip install -q -e . 2>&1 | tail -2 ; true"
    )
    data = _tar_workspace(root)
    shell = (
        "cd /tmp && tar -xf - && cd /tmp/app && "
        f"mkdir -p {mkdirs} 2>/dev/null ; {install} ; "
        f"( {start} > /tmp/app.log 2>&1 & ) ; "
        f"for i in $(seq 1 80); do curl -s -o /dev/null http://127.0.0.1:{port}/ 2>/dev/null && break; sleep 0.5; done ; "
        f"echo '==RESP==' ; curl -s --max-time 8 'http://127.0.0.1:{port}{path}' 2>/dev/null ; "
        "echo ; echo '==APPLOG==' ; tail -c 900 /tmp/app.log 2>/dev/null"
    )
    net = [] if settings.sandbox_allow_network else ["--network", "none"]
    cmd = ["docker", "run", "--rm", "-i", *net,
           "--memory", "1g", "--cpus", "2", "--pids-limit", "256",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           image, "sh", "-c", shell]
    try:
        r = subprocess.run(cmd, input=data, capture_output=True,
                           timeout=settings.sandbox_build_timeout_sec)
        out = (r.stdout or b"").decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return {"attempted": True, "reproduced": False, "poc_code": None, "request": path,
                "observation": None, "reason": "Web 复现超时（依赖安装或启动过慢）。"}
    resp = out.split("==APPLOG==")[0].split("==RESP==")[-1]
    reproduced = oracle in resp
    poc = (f"# PoC: 向漏洞路由发送构造请求触发 {rule['name']}\n"
           f"$ curl 'http://<target>:{port}{path}'")
    return {
        "attempted": True, "reproduced": reproduced, "poc_code": poc,
        "request": f"GET http://127.0.0.1:{port}{path}",
        "observation": (
            f"沙箱内启动目标应用并请求漏洞路由 `{probe['route']}?{probe['param']}=...`，"
            f"响应命中判据 `{oracle}`，漏洞已动态复现。" if reproduced else
            f"已在沙箱内启动应用并发起请求，但响应未命中判据 `{oracle}`"
            f"（可能需额外运行环境，如数据库/服务依赖），静态结论有效。"),
        "oracle_hit": reproduced, "sandbox_log": out[-1900:], "reason": None,
    }


# --------------------------------------------------------------------------- #
# Persistent environment (Provisioner) — stand the app up ONCE, reuse for all PoCs
# --------------------------------------------------------------------------- #
def _dec(b) -> str:
    if isinstance(b, bytes):
        return b.decode("utf-8", "replace")
    return b or ""


def start_persistent(root: Path, task_id: str, lang: str) -> Optional[dict]:
    """docker run -d a kept-alive container and copy the workspace in. Returns an env handle."""
    if lang != "python":
        return None
    image = _ensure_web_image()
    if not image:
        return None
    name = f"veri-prov-{task_id[:10]}"
    _docker("rm", "-f", name)  # clear any stale
    net = [] if settings.sandbox_allow_network else ["--network", "none"]
    r = _docker("run", "-d", "--name", name, *net,
                "--memory", "2g", "--cpus", "2", "--pids-limit", "512",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                image, "tail", "-f", "/dev/null", timeout=60)
    if r.returncode != 0:
        return None
    env = {"container": name, "workdir": "/tmp/app", "port": None, "ready": False,
           "lang": "python", "base_path": ""}
    exec_in(env, "mkdir -p /tmp/app", 30)
    cp = _docker("cp", f"{str(root)}/.", f"{name}:/tmp/app", timeout=180)
    if cp.returncode != 0:
        stop_persistent(env)
        return None
    return env


def exec_in(env: dict, cmd: str, timeout: Optional[int] = None) -> dict:
    timeout = timeout or settings.provisioner_cmd_timeout_sec
    try:
        r = _docker("exec", "-w", env["workdir"], env["container"], "sh", "-c", cmd, timeout=timeout)
        return {"stdout": _dec(r.stdout)[-6000:], "stderr": _dec(r.stderr)[-3000:],
                "exit_code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "command timeout", "exit_code": -1}
    except Exception as e:  # pragma: no cover
        return {"stdout": "", "stderr": f"exec error: {e}", "exit_code": -1}


def exec_detached(env: dict, cmd: str) -> None:
    try:
        _docker("exec", "-d", "-w", env["workdir"], env["container"], "sh", "-c",
                f"{cmd} > /tmp/app.log 2>&1", timeout=30)
    except Exception:
        pass


def check_ready(env: dict, port: int, path: str = "/") -> dict:
    r = exec_in(env, f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 "
                     f"http://127.0.0.1:{port}{path}", 20)
    code = (r["stdout"] or "").strip()[-3:]
    return {"up": code.isdigit() and code != "000", "status": code}


def probe_running(env: dict, path: str) -> str:
    r = exec_in(env, f"curl -s --max-time 8 'http://127.0.0.1:{env.get('port')}{path}'", 20)
    return r["stdout"]


def stop_persistent(env: Optional[dict]) -> None:
    if env and env.get("container"):
        try:
            _docker("rm", "-f", env["container"], timeout=30)
        except Exception:
            pass


def deterministic_provision(root: Path, env: dict) -> dict:
    """Cheap, zero-token first attempt: install detected frameworks + requirements,
    run Django migrations if present, start the app, wait for readiness."""
    import time as _t
    pys = _py_files(root)
    fw = " ".join(_detect_frameworks(pys))
    if fw:
        exec_in(env, f"pip install -q {fw} 2>&1 | tail -3 || true", 240)
    exec_in(env, "[ -f requirements.txt ] && pip install -q -r requirements.txt 2>&1 | tail -3 || true", 300)
    exec_in(env, "mkdir -p /var/data /data /uploads 2>/dev/null || true", 20)
    if (root / "manage.py").exists():
        exec_in(env, "python manage.py migrate --noinput 2>&1 | tail -3 || true", 180)
    start = _derive_start(root, pys)
    if not start:
        return {"ready": False, "reason": "未能推导启动命令。"}
    cmd, port = start
    exec_detached(env, cmd)
    for _ in range(40):
        if check_ready(env, port)["up"]:
            env["port"] = port
            env["ready"] = True
            return {"ready": True, "port": port, "start": cmd}
        _t.sleep(0.5)
    tail = exec_in(env, "tail -c 600 /tmp/app.log", 20)["stdout"]
    return {"ready": False, "port": port, "reason": "应用未在预期端口就绪。", "log": tail}


def _env_payload_for(rid: str) -> Tuple[Optional[str], Optional[str]]:
    p, o = _payload_for(rid)
    if p:
        return p, o
    if rid == "sql-injection":
        return "1'", None   # error-based; oracle handled by _oracle_hit
    return None, None


def _oracle_hit(rid: str, oracle: Optional[str], body: str) -> bool:
    if rid == "sql-injection":
        b = (body or "").lower()
        return any(k in b for k in ["sql", "syntax", "operationalerror", "sqlite",
                                     "mysql", "1064", "unrecognized token", "psycopg"])
    return bool(oracle) and oracle in (body or "")


def reproduce_via_env(root: Path, candidate: dict, env: dict) -> Optional[dict]:
    """Fire a PoC at the already-running provisioned app (reused across candidates)."""
    if not env or not env.get("ready") or not env.get("port"):
        return None
    rule = rule_by_id(candidate.get("rule_id", ""))
    if not rule or not rule.get("reproducible"):
        return None
    rel = candidate["location"]["file"]
    fp = root / rel
    if fp.suffix.lower() != ".py":
        return None
    lines = analysis.read_text(fp).splitlines()
    sink_line = candidate["location"]["line"]
    ri = _find_route(lines, sink_line)
    if not ri:
        return None
    route, rline = ri
    param = _find_param(lines, rline, sink_line)
    if not param:
        return None
    base = env.get("base_path", "")

    # SQL injection: boolean-differential probe (true vs false), robust when a DB is
    # present (seeded by the Provisioner). Also catches error-based leakage.
    if rule["id"] == "sql-injection":
        true_payload = "1' OR '1'='1"
        false_payload = "1' AND '1'='2"
        tp = base + f"{route}?{param}={quote(true_payload, safe='')}"
        fp = base + f"{route}?{param}={quote(false_payload, safe='')}"
        tb, fb = probe_running(env, tp), probe_running(env, fp)
        reproduced = _sqli_bool_diff(tb, fb)
        path = tp
        body = f"[TRUE]{(tb or '')[:400]}\n[FALSE]{(fb or '')[:400]}"
    else:
        payload, oracle = _env_payload_for(rule["id"])
        if not payload:
            return None
        path = base + f"{route}?{param}={quote(payload, safe='')}"
        body = probe_running(env, path)
        reproduced = _oracle_hit(rule["id"], oracle, body)

    return {
        "attempted": True, "reproduced": reproduced,
        "poc_code": f"# PoC(常驻环境)\n$ curl 'http://<target>:{env['port']}{path}'",
        "request": f"GET {path}",
        "observation": (
            f"向常驻应用环境请求漏洞路由 `{route}?{param}=...`，响应命中判据，漏洞已动态复现。"
            if reproduced else
            f"已向常驻环境发起请求，但未命中判据（响应片段：{(body or '')[:150]!r}）。"),
        "oracle_hit": reproduced, "sandbox_log": (body or "")[:1800], "reason": None,
    }


def _sqli_bool_diff(true_body: str, false_body: str) -> bool:
    t = (true_body or "").strip()
    f = (false_body or "").strip()
    # error-based leakage
    if any(k in t.lower() for k in ["sql", "syntax", "operationalerror", "sqlite",
                                     "1064", "unrecognized token", "psycopg"]):
        return True
    empty = {"[]", "()", "null", "none", "", "{}", "[[]]"}
    # boolean-based: TRUE payload returns rows, FALSE returns none, and they differ
    if t != f and f.lower() in empty and t.lower() not in empty:
        return True
    if t != f and f.lower() in empty and len(t) > len(f) + 4:
        return True
    return False


# --------------------------------------------------------------------------- #
# CLI reproduction
# --------------------------------------------------------------------------- #
def _run_cli(root: Path, candidate: dict, rule: dict, lang: str) -> dict:
    image = _CLI_IMAGE[lang]
    if not _image_present(image):
        return {"attempted": True, "reproduced": False, "poc_code": None, "request": None,
                "observation": None,
                "reason": f"沙箱镜像 {image} 不在本地（不自动拉取以节省磁盘），回落静态结论。"}
    content = (root / candidate["location"]["file"]).read_text(encoding="utf-8", errors="replace")
    marker = _marker()
    rid = candidate["rule_id"]
    if rid == "command-injection":
        payload, oracle = f";echo {marker}", marker
    elif rid == "code-injection":
        payload, oracle = f"__import__('sys').stdout.write('{marker}')", marker
    elif rid == "path-traversal":
        payload, oracle = "../../../../../../etc/passwd", "root:"
    else:
        payload, oracle = marker, marker
    ext = "py" if lang == "python" else "js"
    runner = "python t.py" if lang == "python" else "node t.js"
    shell = (f"cd /tmp && cat > t.{ext} && "
             f"timeout {settings.sandbox_timeout_sec} {runner} '{payload}' 2>&1 || true")
    cmd = ["docker", "run", "--rm", "-i", "--network", "none",
           "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "--user", "1000:1000",
           image, "sh", "-c", shell]
    try:
        r = subprocess.run(cmd, input=content, capture_output=True, text=True,
                           timeout=settings.sandbox_timeout_sec + 15)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return {"attempted": True, "reproduced": False, "poc_code": None, "request": None,
                "observation": None, "reason": "沙箱执行超时。"}
    reproduced = oracle in out
    return {
        "attempted": True, "reproduced": reproduced,
        "poc_code": f"# PoC: 以参数注入触发 {rule['name']}\n$ {runner} '{payload}'",
        "request": f"argv[1] = {payload!r}",
        "observation": (f"沙箱输出命中判据 `{oracle}`，漏洞已复现。" if reproduced
                         else f"沙箱执行完成但未命中判据 `{oracle}`。"),
        "oracle_hit": reproduced, "sandbox_log": out[:2000], "reason": None,
    }
