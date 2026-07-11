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

import base64
import hashlib
import io
import random
import re
import shlex
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
_SKIP_TAR = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".idea"}

# The provisioning / verification / web-repro image. Two layers of pre-baked tooling
# every run would otherwise waste steps+tokens discovering it lacks:
#   1) universal build/dev toolchain (gcc/make/git/curl/wget/unzip/pkg-config/ps) —
#      language-agnostic, no dependency conflicts.
#   2) the Validator's professional verification/reproduction tools: sqlmap (SQLi
#      confirm/exploit), strace (syscall-level runtime debugging), mysql client (query /
#      seed / white-box general-log), jq, and nuclei (templated config/exposure checks,
#      best-effort download).
# Language runtimes / DB SERVERS (php, mysql-server, node…) are NOT baked in (they bloat
# the image and vary per project) — the Provisioner apt-installs those on demand, which
# works because the container keeps the caps apt/dpkg need.
_WEB_DOCKERFILE = (
    "FROM python:3.11-slim\n"
    "ENV DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1\n"
    "RUN apt-get update && apt-get install -y --no-install-recommends "
    "build-essential git curl wget unzip ca-certificates pkg-config procps "
    "strace default-mysql-client jq sqlmap "
    # non-web dynamic verification: gcc's ASan (libasan, via build-essential) works out of
    # the box; clang needs its compiler-rt (libclang-rt-dev) to link -fsanitize. gdb for
    # crash triage; netcat/socat for raw TCP/UDP protocol interaction with network daemons.
    "clang llvm libclang-rt-dev gdb netcat-openbsd socat "
    "&& rm -rf /var/lib/apt/lists/*\n"
    # nuclei: best-effort (build never fails if the download is unavailable)
    "RUN NURL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest "
    "| grep -o 'https://[^\"]*linux_amd64.zip' | head -1); "
    "( [ -n \"$NURL\" ] && curl -sL \"$NURL\" -o /tmp/n.zip && unzip -o /tmp/n.zip -d /usr/local/bin nuclei "
    "&& chmod +x /usr/local/bin/nuclei ) || true\n"
)

# tag carries a short hash of the Dockerfile → auto-rebuilds when the recipe changes,
# reuses the cached image otherwise.
_WEB_IMAGE_TAG = (f"{settings.sandbox_image_prefix}-env-"
                  + hashlib.md5(_WEB_DOCKERFILE.encode()).hexdigest()[:8])

# Caps the persistent PROVISIONING container needs so `apt-get install` (dpkg chowns
# files) and services that drop root (mysql/apache → setuid/setgid) actually work.
# Everything else stays dropped; the container is still ephemeral, resource-capped,
# network-limited, and has no host mount.
_PROV_CAPS = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "SETUID", "SETGID",
              "KILL", "SETPCAP", "NET_BIND_SERVICE"]


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
        # richer toolchain layer → allow more time for the one-time build
        b = subprocess.run(["docker", "build", "-t", _WEB_IMAGE_TAG, "-"],
                           input=_WEB_DOCKERFILE.encode(), capture_output=True, timeout=600)
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


# Map a project's dominant source language → the runtime family we stand it up with.
# The base container is Debian (python:3.11-slim + apt); Python is ready out of the box,
# node/php runtimes are apt-installed on demand by the deterministic/LLM provisioner.
_LANG_RUNTIME = {"python": "python", "javascript": "node", "typescript": "node",
                 "node": "node", "php": "php"}


def _runtime_for(lang: str) -> str:
    return _LANG_RUNTIME.get((lang or "").lower(), "python")


def start_persistent(root: Path, task_id: str, lang: str) -> Optional[dict]:
    """docker run -d a kept-alive container and copy the workspace in. Returns an env handle.
    Language-agnostic: the container is Debian+apt, so python/node/php apps all stand up here
    (the runtime is apt-installed on demand for non-python)."""
    image = _ensure_web_image()
    if not image:
        return None
    runtime = _runtime_for(lang)
    name = f"veri-prov-{task_id[:10]}"
    _docker("rm", "-f", name)  # clear any stale
    net = [] if settings.sandbox_allow_network else ["--network", "none"]
    caps: List[str] = []
    for c in _PROV_CAPS:
        caps += ["--cap-add", c]
    r = _docker("run", "-d", "--name", name, *net,
                "--memory", "2g", "--cpus", "2", "--pids-limit", "512",
                "--cap-drop", "ALL", *caps,
                image, "tail", "-f", "/dev/null", timeout=60)
    if r.returncode != 0:
        return None
    env = {"container": name, "workdir": "/tmp/app", "port": None, "ready": False,
           "lang": (lang or "python"), "runtime": runtime, "base_path": ""}
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


# --------------------------------------------------------------------------- #
# Non-web dynamic verification primitives
#   - network daemons speaking a NON-HTTP protocol (VPN mgmt / redis / smtp / custom
#     TCP·UDP): net_interact() opens a socket, sends crafted bytes, reads the reply.
#   - native / CLI / library targets (C·C++·Go·Rust binaries, parsers, harnesses):
#     run_target() feeds crafted argv/stdin/input-files and captures structured
#     crash evidence — terminating SIGNAL (SEGV/ABRT/…) and any ASan/UBSan report,
#     which is DEFINITIVE dynamic proof of a memory-safety / UB vulnerability.
# Both run inside the persistent provisioning container (python3 + clang/gdb/nc/socat
# are pre-baked), so they need no host access.
# --------------------------------------------------------------------------- #
_SIGNALS = {2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT",
            7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 11: "SIGSEGV", 13: "SIGPIPE",
            15: "SIGTERM"}
# a terminating signal from one of these = a memory-safety / UB / arithmetic crash
_CRASH_SIGNALS = {4, 6, 7, 8, 11}
_SAN_MARKERS = (
    "ERROR: AddressSanitizer", "AddressSanitizer", "SUMMARY: AddressSanitizer",
    "UndefinedBehaviorSanitizer", "SUMMARY: UndefinedBehaviorSanitizer", "runtime error:",
    "LeakSanitizer", "detected memory leaks", "heap-buffer-overflow", "stack-buffer-overflow",
    "global-buffer-overflow", "heap-use-after-free", "use-after-free", "double-free",
    "attempting double-free", "SEGV on unknown address", "stack-overflow",
    "ThreadSanitizer", "data race",
)


def _classify_run(exit_code: Optional[int], out: str) -> dict:
    """Turn a raw (exit_code, combined stdout+stderr) into structured crash/sanitizer
    evidence. Pure function → unit-testable without Docker."""
    info = {"exit_code": exit_code, "signal": None, "signal_name": None,
            "crashed": False, "timed_out": False, "memory_error": False, "sanitizer": None}
    if exit_code == 124:                      # coreutils `timeout` reached its limit (TERM)
        info["timed_out"] = True
    elif exit_code == 137:                    # timeout -s KILL had to hard-kill (hang)
        info["timed_out"] = True
    elif isinstance(exit_code, int) and exit_code > 128:
        sig = exit_code - 128
        info["signal"] = sig
        info["signal_name"] = _SIGNALS.get(sig, f"SIG{sig}")
        if sig in _CRASH_SIGNALS:
            info["crashed"] = True
    text = out or ""
    hit = next((m for m in _SAN_MARKERS if m in text), None)
    if hit:
        info["memory_error"] = True
        idx = text.find(hit)
        info["sanitizer"] = text[max(0, idx - 60): idx + 1400]
    return info


def _net_interact(env: dict, port: int, proto: str = "tcp", payload_b64: str = "",
                  read_timeout: float = 5.0, read_bytes: int = 65536) -> dict:
    """Open a TCP/UDP socket to 127.0.0.1:port inside the container, optionally send a
    crafted payload (base64 → raw bytes, so binary/quotes are safe), read the reply.
    Driven by a python3 one-liner (python3 is in the base image)."""
    proto = (proto or "tcp").lower()
    py = (
        "import socket,sys,base64,time\n"
        f"data=base64.b64decode({payload_b64!r}) if {payload_b64!r} else b''\n"
        f"proto={proto!r}; port={int(port)}; tout=float({float(read_timeout)}); cap={int(read_bytes)}\n"
        "try:\n"
        "  if proto=='udp':\n"
        "    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(tout)\n"
        "    s.sendto(data,('127.0.0.1',port))\n"
        "    try: resp=s.recvfrom(cap)[0]\n"
        "    except socket.timeout: resp=b''\n"
        "  else:\n"
        "    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(tout)\n"
        "    s.connect(('127.0.0.1',port))\n"
        "    if data: s.sendall(data)\n"
        "    chunks=[]; end=time.time()+tout\n"
        "    while time.time()<end:\n"
        "      try:\n"
        "        s.settimeout(max(0.1,end-time.time())); b=s.recv(4096)\n"
        "      except socket.timeout: break\n"
        "      if not b: break\n"
        "      chunks.append(b)\n"
        "      if sum(len(x) for x in chunks)>=cap: break\n"
        "    resp=b''.join(chunks)\n"
        "  sys.stdout.write('__NETOK__'+base64.b64encode(resp).decode())\n"
        "except Exception as e:\n"
        "  sys.stdout.write('__NETERR__'+repr(e))\n"
    )
    b64 = base64.b64encode(py.encode()).decode()
    r = exec_in(env, f"echo {b64} | base64 -d | python3", int(read_timeout) + 15)
    out = r.get("stdout", "") or ""
    if "__NETOK__" in out:
        enc = out.split("__NETOK__", 1)[1].strip()
        try:
            raw = base64.b64decode(enc)
        except Exception:
            raw = b""
        return {"ok": True, "bytes": len(raw), "response_b64": enc,
                "response": raw.decode("utf-8", "replace")[-4000:]}
    if "__NETERR__" in out:
        return {"ok": False, "error": out.split("__NETERR__", 1)[1].strip()[:400]}
    return {"ok": False, "error": (r.get("stderr") or "无响应/连接失败")[:400]}


def run_target(env: dict, cmd: str, stdin_b64: str = "", input_files: Optional[list] = None,
               timeout: Optional[int] = None) -> dict:
    """Run a command (the target binary / a small harness / a fuzz replay) inside the
    container with crafted input, and return STRUCTURED crash evidence. Crafted input
    files are materialized from base64 first (payloads never touch the shell). A
    terminating SIGSEGV/SIGABRT or an AddressSanitizer/UBSan report is definitive
    dynamic proof of a memory-safety / undefined-behaviour vulnerability."""
    timeout = int(timeout or settings.sandbox_timeout_sec)
    for f in (input_files or [])[:12]:
        path = (f or {}).get("path")
        content_b64 = (f or {}).get("content_b64", "")
        if not path:
            continue
        exec_in(env, f"mkdir -p \"$(dirname {shlex.quote(path)})\" 2>/dev/null; "
                     f"echo {shlex.quote(content_b64)} | base64 -d > {shlex.quote(path)}", 60)
    stdin_part = f"echo {shlex.quote(stdin_b64)} | base64 -d | " if stdin_b64 else ""
    # ASAN/UBSAN: symbolize + abort on error so the exit code carries the crash signal.
    prelude = ("export ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1 "
               "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1; ")
    full = (f"{prelude}{stdin_part}timeout -s KILL {timeout} sh -c {shlex.quote(cmd)} 2>&1; "
            f"echo __RC__$?")
    r = exec_in(env, full, timeout + 25)
    out = r.get("stdout", "") or ""
    rc: Optional[int] = None
    if "__RC__" in out:
        out, _, tail = out.rpartition("__RC__")
        try:
            rc = int(re.match(r"\d+", tail.strip()).group())
        except Exception:
            rc = None
    info = _classify_run(rc, out)
    info["cmd"] = cmd
    info["stdout"] = out[-4000:]
    info["stderr"] = (r.get("stderr") or "")[-800:]
    return info


def _tcp_up(env: dict, port: int) -> bool:
    return bool(_net_interact(env, port, "tcp", "", read_timeout=3, read_bytes=1024).get("ok"))


def _udp_up(env: dict, port: int) -> bool:
    """UDP is connectionless — readiness = a process has the port bound (kernel table)."""
    hexport = f"{int(port):04X}"
    r = exec_in(env, "cat /proc/net/udp /proc/net/udp6 2>/dev/null", 20)
    return f":{hexport}" in (r.get("stdout", "") or "")


def probe_ready(env: dict, port: Optional[int] = None, kind: str = "http",
                proto: str = "tcp", path: str = "/", smoke_cmd: str = "") -> dict:
    """Protocol/target-kind-aware readiness. Generalizes check_ready beyond HTTP so
    non-web targets can be marked ready:
      http    → HTTP status code responds (existing behavior)
      network → TCP handshake succeeds / UDP port is bound
      cli     → the target command is runnable (a crash still counts as 'runnable')"""
    kind = (kind or "http").lower()
    if kind == "network":
        p = int(port or env.get("port") or 0)
        up = _udp_up(env, p) if (proto or "tcp").lower() == "udp" else _tcp_up(env, p)
        return {"up": up, "kind": "network", "proto": (proto or "tcp").lower(), "port": p}
    if kind == "cli":
        if smoke_cmd:
            r = run_target(env, smoke_cmd, timeout=min(60, settings.sandbox_timeout_sec))
            return {"up": r.get("exit_code") != 127, "kind": "cli",   # 127 = command not found
                    "smoke": {k: r.get(k) for k in ("exit_code", "signal_name", "memory_error")}}
        return {"up": True, "kind": "cli", "note": "CLI/原生目标无常驻服务，就绪=可执行目标命令"}
    res = check_ready(env, int(port or env.get("port") or 0), path)
    res["kind"] = "http"
    return res


def stop_persistent(env: Optional[dict]) -> None:
    if env and env.get("container"):
        try:
            _docker("rm", "-f", env["container"], timeout=30)
        except Exception:
            pass


def deterministic_provision(root: Path, env: dict) -> dict:
    """Cheap, zero-token first attempt to stand the app up, dispatched by runtime family.
    Anything it can't handle returns ready=False with a reason → the LLM provisioner takes
    over (it can apt-install runtimes and improvise)."""
    runtime = env.get("runtime", "python")
    if runtime == "python":
        return _provision_python(root, env)
    if runtime == "node":
        return _provision_node(root, env)
    if runtime == "php":
        return _provision_php(root, env)
    return {"ready": False, "reason": f"暂无 {runtime} 的确定性搭建路径，转由模型自主搭建。"}


def _wait_ready(env: dict, port: int, cmd: str, tries: int = 40) -> dict:
    import time as _t
    exec_detached(env, cmd)
    for _ in range(tries):
        if check_ready(env, port)["up"]:
            env["port"] = port
            env["ready"] = True
            return {"ready": True, "port": port, "start": cmd}
        _t.sleep(0.5)
    tail = exec_in(env, "tail -c 600 /tmp/app.log", 20)["stdout"]
    return {"ready": False, "port": port, "reason": "应用未在预期端口就绪。", "log": tail}


def _provision_python(root: Path, env: dict) -> dict:
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
        return {"ready": False, "reason": "未能推导 Python 启动命令。"}
    return _wait_ready(env, start[1], start[0])


def _provision_node(root: Path, env: dict) -> dict:
    # ensure a node runtime (base image is python-only) then install deps + start
    chk = exec_in(env, "command -v node >/dev/null 2>&1 && echo Y || echo N", 20)
    if "Y" not in (chk.get("stdout") or ""):
        exec_in(env, "apt-get update -qq && apt-get install -y -qq nodejs npm 2>&1 | tail -3 || true", 600)
    if (root / "package.json").exists():
        exec_in(env, "npm install --no-audit --no-fund 2>&1 | tail -5 || true", 600)
    start = _derive_start_node(root)
    if not start:
        return {"ready": False, "reason": "未能推导 Node 启动命令（无 package.json start/main 或 server/app/index.js）。"}
    return _wait_ready(env, start[1], start[0])


def _provision_php(root: Path, env: dict) -> dict:
    chk = exec_in(env, "command -v php >/dev/null 2>&1 && echo Y || echo N", 20)
    if "Y" not in (chk.get("stdout") or ""):
        exec_in(env, "apt-get update -qq && apt-get install -y -qq "
                     "php-cli php-mysql php-sqlite3 php-xml php-mbstring php-curl php-gd 2>&1 | tail -3 || true", 600)
    if (root / "composer.json").exists():
        exec_in(env, "command -v composer >/dev/null 2>&1 || apt-get install -y -qq composer 2>&1 | tail -2 ; "
                     "composer install --no-interaction --no-progress 2>&1 | tail -5 || true", 600)
    docroot = _php_docroot(root)
    port = 8000
    return _wait_ready(env, port, f"php -S 127.0.0.1:{port} -t '{docroot}'", tries=30)


def _derive_start_node(root: Path) -> Optional[Tuple[str, int]]:
    import json as _json
    port = _guess_node_port(root)
    pj = root / "package.json"
    if pj.exists():
        try:
            data = _json.loads(analysis.read_text(pj) or "{}")
        except Exception:
            data = {}
        if isinstance(data.get("scripts"), dict) and data["scripts"].get("start"):
            return ("npm start", port)
        main = data.get("main")
        if main and (root / main).exists():
            return (f"node '{main}'", port)
    for cand in ("server.js", "app.js", "index.js", "src/index.js", "src/server.js", "bin/www"):
        if (root / cand).exists():
            return (f"node '{cand}'", port)
    return None


def _guess_node_port(root: Path) -> int:
    for p, lang in analysis.iter_source_files(root):
        if lang not in ("javascript", "typescript"):
            continue
        txt = analysis.read_text(p)
        m = re.search(r"\.listen\(\s*(\d{2,5})", txt) or re.search(r"PORT\s*[|=]{1,2}\s*(\d{2,5})", txt)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                pass
    return 3000


def _php_docroot(root: Path) -> str:
    for d in ("public", "web", "htdocs", "www", "src/public"):
        if (root / d / "index.php").exists():
            return d
    if (root / "index.php").exists():
        return "."
    try:
        for p in root.rglob("index.php"):
            if any(seg in _SKIP_TAR for seg in p.parts):
                continue
            rel = str(p.parent.relative_to(root)).replace("\\", "/")
            return rel or "."
    except Exception:
        pass
    return "."


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
