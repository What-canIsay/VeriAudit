"""Professional code-audit scanner integration layer.

Mirrors the tools a real auditor reaches for — each with a distinct, non-overlapping
role, exposed to the LLM as callable tools (see agents/tools.py):

  · semgrep_scan     — pattern SAST, multi-language, breadth   (bandit = offline fallback)
  · codeql_scan      — semantic dataflow analysis, precision, heavy (deep mode)
  · secret_scan      — gitleaks: hardcoded secrets / credentials
  · dependency_scan  — osv-scanner: known-CVE vulnerable dependencies (SCA)

Every runner probes availability (graceful degradation), enforces a timeout, and
returns candidates normalized to the pipeline's candidate shape. Nothing here spends
tokens — this is the cheap, high-recall breadth the LLM orchestrates.
"""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from .config import settings


def _has_mod(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False

CWE_NAMES = {
    "22": "Path Traversal", "78": "OS Command Injection", "79": "Cross-Site Scripting",
    "89": "SQL Injection", "94": "Code Injection", "502": "Insecure Deserialization",
    "601": "Open Redirect", "611": "XXE", "798": "Hardcoded Credentials",
    "918": "SSRF", "1336": "Server-Side Template Injection", "1395": "Vulnerable Dependency",
}


def available() -> Dict[str, bool]:
    return {
        "semgrep": bool(shutil.which("semgrep")) or _has_mod("bandit"),
        "codeql": bool(shutil.which("codeql")),
        "gitleaks": bool(shutil.which("gitleaks")),
        "osv": bool(shutil.which("osv-scanner")),
    }


def _rel(root: Path, p: str) -> str:
    try:
        pp = Path(p)
        return str(pp.relative_to(root)).replace("\\", "/") if pp.is_absolute() else p.replace("\\", "/")
    except Exception:
        return str(p).replace("\\", "/")


def _sev(s: str) -> str:
    s = (s or "").lower()
    return {"error": "high", "critical": "critical", "high": "high", "warning": "medium",
            "medium": "medium", "moderate": "medium", "info": "low", "low": "low",
            "note": "low"}.get(s, "medium")


def _cwe_label(cwe_id: str, fallback: str = "Security Issue") -> str:
    cwe_id = str(cwe_id).replace("CWE-", "").strip()
    name = CWE_NAMES.get(cwe_id, fallback)
    return f"CWE-{cwe_id} {name}" if cwe_id.isdigit() else fallback


def _run(cmd: List[str], timeout: int, cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)


# --------------------------------------------------------------------------- #
# semgrep_scan  (breadth) — falls back to bandit for offline Python coverage
# --------------------------------------------------------------------------- #
def run_semgrep(root: Path, timeout: Optional[int] = None) -> List[dict]:
    timeout = timeout or settings.scanner_timeout_sec
    if shutil.which("semgrep"):
        try:
            r = _run(["semgrep", "scan", "--config", "auto", "--json", "--quiet",
                      "--timeout", str(min(60, timeout)), str(root)], timeout)
            data = json.loads(r.stdout or "{}")
            out = _parse_semgrep(root, data)
            if out:
                return out
        except Exception:
            pass
    # offline fallback: bandit (Python, invoked as a module — no PATH dependency)
    if _has_mod("bandit"):
        return run_bandit(root, timeout)
    return []


def _parse_semgrep(root: Path, data: dict) -> List[dict]:
    out = []
    for res in data.get("results", [])[:120]:
        extra = res.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        cwe = meta.get("cwe")
        cwe_id = ""
        if isinstance(cwe, list) and cwe:
            cwe_id = str(cwe[0]).split(":")[0].replace("CWE-", "").strip()
        elif isinstance(cwe, str):
            cwe_id = cwe.split(":")[0].replace("CWE-", "").strip()
        out.append(_mk(root, res.get("path", ""), res.get("start", {}).get("line", 1),
                       _cwe_label(cwe_id, "SAST Finding"), _sev(extra.get("severity", "medium")),
                       "semgrep", extra.get("message", res.get("check_id", "semgrep rule")),
                       extra.get("lines", ""), 0.72, {"rule": res.get("check_id")}))
    return out


def run_bandit(root: Path, timeout: Optional[int] = None) -> List[dict]:
    timeout = timeout or settings.scanner_timeout_sec
    if not _has_mod("bandit"):
        return []
    try:
        r = _run([sys.executable, "-m", "bandit", "-r", str(root), "-f", "json", "-q"], timeout)
        data = json.loads(r.stdout or "{}")
    except Exception:
        return []
    out = []
    for res in data.get("results", [])[:120]:
        tid = res.get("test_id", "")
        # B4xx are import-blacklist warnings (flag an import, not a real sink) — noisy FPs.
        if re.match(r"^B4\d\d$", tid):
            continue
        cwe = (res.get("issue_cwe") or {}).get("id", "")
        out.append(_mk(root, res.get("filename", ""), res.get("line_number", 1),
                       _cwe_label(cwe, "Python Security Issue"), _sev(res.get("issue_severity", "medium")),
                       "semgrep", res.get("issue_text", ""), res.get("code", ""), 0.7,
                       {"rule": res.get("test_id"), "engine": "bandit"}))
    return out


# --------------------------------------------------------------------------- #
# codeql_scan  (semantic dataflow, precision) — heavy; deep mode only
# --------------------------------------------------------------------------- #
def run_codeql(root: Path, languages: List[str], timeout: Optional[int] = None) -> List[dict]:
    timeout = timeout or max(600, settings.scanner_timeout_sec * 3)
    if not shutil.which("codeql") or not languages:
        return []
    cql_lang = {"python": "python", "javascript": "javascript", "java": "java",
                "go": "go"}.get(languages[0])
    if not cql_lang:
        return []
    try:
        with tempfile.TemporaryDirectory() as td:
            db = str(Path(td) / "db")
            sarif = str(Path(td) / "out.sarif")
            _run(["codeql", "database", "create", db, f"--language={cql_lang}",
                  f"--source-root={root}", "--overwrite"], timeout)
            _run(["codeql", "database", "analyze", db,
                  f"{cql_lang}-security-and-quality.qls", "--format=sarifv2.1.0",
                  f"--output={sarif}", "--rerun"], timeout)
            return _parse_sarif(root, Path(sarif).read_text(encoding="utf-8"), "codeql")
    except Exception:
        return []


def _parse_sarif(root: Path, text: str, origin: str) -> List[dict]:
    try:
        doc = json.loads(text)
    except Exception:
        return []
    out = []
    for run in doc.get("runs", []):
        for res in run.get("results", [])[:120]:
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            path = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", 1)
            msg = res.get("message", {}).get("text", res.get("ruleId", ""))
            out.append(_mk(root, path, line, _cwe_label("", "Dataflow Finding"),
                           _sev(res.get("level", "warning")), origin, msg, "", 0.8,
                           {"rule": res.get("ruleId")}))
    return out


# --------------------------------------------------------------------------- #
# secret_scan  (gitleaks) — hardcoded secrets / credentials
# --------------------------------------------------------------------------- #
def run_gitleaks(root: Path, timeout: Optional[int] = None) -> List[dict]:
    timeout = timeout or settings.scanner_timeout_sec
    if not shutil.which("gitleaks"):
        return []
    try:
        with tempfile.TemporaryDirectory() as td:
            rep = str(Path(td) / "gl.json")
            _run(["gitleaks", "detect", "--source", str(root), "--no-git",
                  "--report-format", "json", "--report-path", rep, "--redact"], timeout)
            data = json.loads(Path(rep).read_text(encoding="utf-8") or "[]")
    except Exception:
        return []
    out = []
    for f in (data or [])[:80]:
        out.append(_mk(root, f.get("File", ""), f.get("StartLine", 1),
                       "CWE-798 Hardcoded Credentials", "medium", "gitleaks",
                       f.get("Description", "secret detected") + f" [{f.get('RuleID','')}]",
                       "", 0.85, {"rule": f.get("RuleID"), "kind": "secret"}))
    for c in out:
        c["rule_id"] = "hardcoded-secret"
    return out


# --------------------------------------------------------------------------- #
# dependency_scan  (osv-scanner) — known-CVE vulnerable dependencies (SCA)
# --------------------------------------------------------------------------- #
def run_osv(root: Path, timeout: Optional[int] = None) -> List[dict]:
    timeout = timeout or settings.scanner_timeout_sec
    if not shutil.which("osv-scanner"):
        return []
    try:
        r = _run(["osv-scanner", "--format", "json", "-r", str(root)], timeout)
        data = json.loads(r.stdout or "{}")
    except Exception:
        return []
    out = []
    for result in data.get("results", []):
        src = result.get("source", {}).get("path", "")
        for pkg in result.get("packages", []):
            info = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", [])[:5]:
                vid = vuln.get("id", "")
                sev = "high" if any(s.get("type") for s in vuln.get("severity", [])) else "medium"
                c = _mk(root, src, 1, "CWE-1395 Vulnerable Dependency", sev, "osv",
                        f"{info.get('name')}@{info.get('version')} — {vid}: "
                        + (vuln.get("summary", "") or "")[:160], "", 0.8,
                        {"package": info.get("name"), "version": info.get("version"),
                         "vuln_id": vid, "kind": "dependency"})
                c["rule_id"] = "vulnerable-dependency"
                out.append(c)
    return out


# --------------------------------------------------------------------------- #
def _mk(root: Path, path: str, line, vuln_type: str, severity: str, origin: str,
        rationale: str, snippet: str, conf: float, meta: dict) -> dict:
    return {
        "rule_id": origin, "vuln_type": vuln_type, "_severity": severity, "origin": origin,
        "self_confidence": conf, "rationale": f"[{origin}] {rationale}"[:400],
        "location": {"file": _rel(root, path), "line": int(line or 1),
                     "function": None, "snippet": (snippet or "")[:300]},
        "lang": "unknown", "_source": None, "_sanitized": False, "_meta": meta,
    }
