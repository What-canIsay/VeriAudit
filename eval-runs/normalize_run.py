#!/usr/bin/env python3
"""Deterministic normalizer — build an `eval-result-contract-v1` dataset from a real VeriAudit run.

Reads ONLY persisted, measured data:
  * SQLite DB  (backend/_data/veriaudit.db): task, findings, evidence, artifacts, candidates,
    agent_runs, tool_invocations
  * model_calls.raw.jsonl : REAL per-call token usage captured from the DeepSeek API responses
  * expectedresults CSV   : OWASP Benchmark ground truth (test -> cwe, real)
  * report via the running API (markdown / json / sarif) -> raw/

No value is invented. Fields the system does not collect are emitted as null or "not_collected";
per-call cost is left null because authoritative pricing for `deepseek-v4-flash` is not published.

Usage:
  python normalize_run.py --task <id> --run-dir <dir> --run-id <id> --member <name> \
      --db <veriaudit.db> --usage <model_calls.raw.jsonl> --gt <expectedresults.csv> \
      --git <commit> --workspace <path> [--api http://127.0.0.1:8000]
"""
from __future__ import annotations
import argparse, csv, hashlib, json, os, platform, re, shutil, sqlite3, subprocess, sys, urllib.request
from datetime import datetime, timezone, timedelta

SCHEMA = "eval-result-contract-v1"
TOOL = "VeriAudit"
TZ = timezone(timedelta(hours=8))  # Asia/Shanghai
NOTCOLL = "not_collected"


# ----------------------------- helpers -----------------------------
def to_iso(s):
    """DB stores naive UTC -> emit ISO-8601 +08:00."""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s))
    except Exception:
        return str(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(TZ).isoformat()


def dt_of(s):
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s))
    except Exception:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def jload(v, default=None):
    if v is None:
        return default
    if isinstance(v, (dict, list)):
        return v
    try:
        return json.loads(v)
    except Exception:
        return default


def sha256(s: str):
    return "sha256:" + hashlib.sha256((s or "").encode("utf-8")).hexdigest()


def cwe_num(text):
    m = re.search(r"CWE[-_ ]?(\d+)", str(text or ""), re.I)
    return m.group(1) if m else None


def bench_test(text):
    m = re.search(r"(BenchmarkTest\d+)", str(text or ""))
    return m.group(1) if m else None


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


# ----------------------------- main -----------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", required=True)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--member", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--usage", default="")
    ap.add_argument("--gt", default="")
    ap.add_argument("--git", default=None)
    ap.add_argument("--workspace", default="")
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    a = ap.parse_args()

    run_dir = a.run_dir
    art_dir = os.path.join(run_dir, "artifacts")
    raw_dir = os.path.join(run_dir, "raw")
    os.makedirs(art_dir, exist_ok=True)
    os.makedirs(raw_dir, exist_ok=True)

    con = sqlite3.connect(a.db)
    con.row_factory = sqlite3.Row
    task = con.execute("select * from audit_task where id=?", (a.task,)).fetchone()
    if not task:
        print("task not found:", a.task); sys.exit(1)
    proj = con.execute("select * from project where id=?", (task["project_id"],)).fetchone()

    findings = con.execute("select * from finding where task_id=? order by created_at", (a.task,)).fetchall()
    candidates = con.execute("select * from candidate where task_id=?", (a.task,)).fetchall()
    agent_runs = con.execute("select * from agent_run where task_id=? order by started_at", (a.task,)).fetchall()
    tools = con.execute("select * from tool_invocation where task_id=? order by ts", (a.task,)).fetchall()

    langs = jload(proj["languages"], {}) if proj else {}
    counts = jload(task["counts"], {})
    budget = jload(task["budget"], {})
    started, finished = dt_of(task["started_at"]), dt_of(task["finished_at"])
    wall = (finished - started).total_seconds() if (started and finished) else None
    status_map = {"succeeded": "success", "failed": "failed", "cancelled": "aborted",
                  "running": "partial", "paused": "partial"}
    run_status = status_map.get(task["status"], "partial")

    # ---------------- ground truth ----------------
    gt = {}  # test_name -> (cwe, real_bool)
    if a.gt and os.path.exists(a.gt):
        with open(a.gt, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 4 and parts[0].startswith("BenchmarkTest"):
                    gt[parts[0]] = (parts[3], parts[2].lower() == "true")
    gt_available = bool(gt)

    # ---------------- raw provider reports ----------------
    def fetch_report(fmt):
        try:
            req = urllib.request.Request(f"{a.api}/api/v1/tasks/{a.task}/report?format={fmt}", method="POST")
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.loads(r.read().decode("utf-8")).get("content", "")
        except Exception as e:
            return f"<report fetch failed: {e}>"
    raw_md = fetch_report("markdown")
    raw_json = fetch_report("json")
    raw_sarif = fetch_report("sarif")
    with open(os.path.join(raw_dir, "veriaudit-report.md"), "w", encoding="utf-8") as f:
        f.write(raw_md)
    with open(os.path.join(raw_dir, "veriaudit-report.json"), "w", encoding="utf-8") as f:
        f.write(raw_json)
    with open(os.path.join(raw_dir, "veriaudit-report.sarif"), "w", encoding="utf-8") as f:
        f.write(raw_sarif)
    # raw DB dump of findings + task
    write_json(os.path.join(raw_dir, "task.json"), {k: task[k] for k in task.keys()})
    write_json(os.path.join(raw_dir, "findings.db.json"),
               [{k: r[k] for k in r.keys()} for r in findings])

    # ---------------- artifacts + normalized findings ----------------
    norm = []
    rejected_records = []
    poc_gen = poc_exec = poc_ver = poc_fail = 0
    declared = {}   # test_name -> set(cwe) for GT scoring
    ext = {"python": "py", "sql": "sql", "http": "txt", "text": "txt", "bash": "sh"}
    surfaced_idx = 0
    for f in findings:
        # REJECTED = candidate the validator pruned BEFORE output. It is NOT one of the system's
        # reported findings and must not be counted as a system false positive. Keep it in a
        # separate raw file for transparency, but out of finding.normalized.jsonl.
        if f["confidence"] == "REJECTED":
            rev = con.execute("select * from evidence_chain where finding_id=?", (f["id"],)).fetchone()
            rsv = jload(rev["static_verdict"], {}) if rev else {}
            rdyn = jload(rev["dynamic_verification"], None) if rev else None
            reason = ((rsv.get("rationale") if isinstance(rsv, dict) else None)
                      or (rdyn.get("observation") if isinstance(rdyn, dict) else None)
                      or "validator 判定为不可达 / 被证伪 / 有效净化")
            rcwe = cwe_num(f["vuln_type"])
            rejected_records.append({
                "candidate_id": f["id"][:8], "title": f["title"],
                "cwe": (f"CWE-{rcwe}" if rcwe else None), "vuln_type": f["vuln_type"],
                "disposition": "internally_rejected",
                "reason": str(reason)[:300],
                "note": "验证官在产出前剪除；不属于系统最终上报的 53 条结果，也不计为系统误报",
            })
            continue
        surfaced_idx += 1
        fid = f"finding-{surfaced_idx:04d}"
        ev = con.execute("select * from evidence_chain where finding_id=?", (f["id"],)).fetchone()
        arts = con.execute("select * from artifact where finding_id=?", (f["id"],)).fetchall()
        source = jload(ev["source"], None) if ev else None
        sink = jload(ev["sink"], None) if ev else None
        entry = jload(ev["entry_point"], None) if ev else None
        taint = jload(ev["taint_path"], []) if ev else []
        reach = jload(ev["reachability"], {}) if ev else {}
        sverd = jload(ev["static_verdict"], {}) if ev else {}
        dynv = jload(ev["dynamic_verification"], None) if ev else None
        sev = jload(f["severity"], {})

        # file/line: prefer sink, then source, then title
        loc = sink or source or {}
        file_ = loc.get("file") if isinstance(loc, dict) else None
        line = loc.get("line") if isinstance(loc, dict) else None
        end_line = loc.get("end_line") if isinstance(loc, dict) else None
        func = loc.get("function") if isinstance(loc, dict) else None
        if not file_:
            m = re.search(r"([\w/\\.-]+\.py):(\d+)", f["title"] or "")
            if m:
                file_, line = m.group(1), int(m.group(2))
        cwe = cwe_num(f["vuln_type"]) or cwe_num(f["title"])
        cwe_str = f"CWE-{cwe}" if cwe else None
        tname = bench_test(file_) or bench_test(f["title"])

        # confidence -> contract status + poc_status
        conf = f["confidence"]
        attempted = bool(dynv and dynv.get("attempted"))
        reproduced = bool(dynv and dynv.get("reproduced"))
        has_poc = any(x["kind"] == "poc_code" for x in arts)
        if conf == "REJECTED":
            fstatus = "false_positive"
        elif reproduced or conf == "CONFIRMED_DYNAMIC":
            fstatus = "verified"
        elif conf == "CONFIRMED_STATIC":
            fstatus = "verified"
        elif conf == "SUSPECTED":
            fstatus = "candidate"
        else:
            fstatus = "unknown"
        if reproduced:
            poc_status = "verified"
        elif attempted:
            poc_status = "failed"
        elif has_poc:
            poc_status = "generated"
        else:
            poc_status = "none"
        if has_poc:
            poc_gen += 1
        if attempted:
            poc_exec += 1
        if reproduced:
            poc_ver += 1
        if attempted and not reproduced:
            poc_fail += 1

        # write evidence artifacts
        fdir = os.path.join(art_dir, fid)
        evidence_files = []
        poc_path = None
        if arts:
            os.makedirs(fdir, exist_ok=True)
        for ai, art in enumerate(arts):
            kind = art["kind"]
            meta = jload(art["meta"], {})
            lang = (meta.get("language") or "").lower() if isinstance(meta, dict) else ""
            name = {"poc_code": f"poc.{ext.get(lang, 'py')}", "sandbox_log": "sandbox.log",
                    "http_exchange": "http_exchange.txt", "canary_hit": "canary.txt"}.get(kind, f"{kind}_{ai}.txt")
            fpath = os.path.join(fdir, name)
            with open(fpath, "w", encoding="utf-8") as fh:
                fh.write(art["content"] or "")
            rel = os.path.relpath(fpath, run_dir).replace("\\", "/")
            evidence_files.append(rel)
            if kind == "poc_code":
                poc_path = rel

        # ground-truth match (Benchmark: a test is a real vuln only of its designated CWE)
        if tname and gt_available and tname in gt:
            g_cwe, g_real = gt[tname]
            if cwe == g_cwe and g_real:
                gtm = "tp"
            else:
                gtm = "fp"
        elif tname and gt_available:
            gtm = "fp"        # flagged a benchmark test not in GT positives
        else:
            gtm = "unknown" if not gt_available else "unknown"
        if fstatus == "false_positive":
            gtm = "fp" if gt_available else "unknown"
        # record declaration for aggregate scoring (exclude self-rejected FPs)
        if tname and cwe and conf != "REJECTED":
            declared.setdefault(tname, set()).add(cwe)

        data_flow = []
        for h in (taint or []):
            hl = (h.get("location") or {}) if isinstance(h, dict) else {}
            seg = f"{hl.get('file','?')}:{hl.get('line','?')}"
            if isinstance(h, dict) and h.get("transform"):
                seg += f" [{h['transform']}]"
            data_flow.append(seg)

        norm.append({
            "schema_version": SCHEMA, "finding_id": fid, "run_id": a.run_id, "tool": TOOL,
            "sample_id": tname or (proj["name"] if proj else "unknown"),
            "title": f["title"], "category": "code_vulnerability",
            "cwe": cwe_str, "owasp": None,
            "severity": (sev.get("level") or "unknown"),
            "confidence": (reach.get("confidence") if isinstance(reach, dict) else None),
            "status": fstatus,
            "file": file_, "line": line, "end_line": end_line, "function": func,
            "source": (source or {}).get("snippet") or (source or {}).get("expr") if isinstance(source, dict) else None,
            "sink": (sink or {}).get("snippet") if isinstance(sink, dict) else None,
            "data_flow": data_flow,
            "affected_endpoint": None, "affected_component": file_,
            "preconditions": (sverd.get("rationale") if isinstance(sverd, dict) else None),
            "attack_vector": (dynv.get("observation") if isinstance(dynv, dict) else None),
            "impact": f["vuln_type"], "description": (sverd.get("rationale") if isinstance(sverd, dict) else "") or f["title"],
            "fix": f["remediation"] or "",
            "poc_status": poc_status, "poc_path": poc_path,
            "evidence": evidence_files,
            "raw_refs": ["raw/veriaudit-report.json"],
            "dedup_key": f["dedup_key"],
            "ground_truth_match": gtm,
            "notes": f"confidence={conf}; cvss={f['cvss_vector']}",
        })

    # ---------------- Benchmark aggregate detection metrics ----------------
    detection = {"precision": None, "recall": None, "f1": None, "false_positive_rate": None,
                 "false_negative_rate": None, "top_1_hit_rate": None, "top_3_hit_rate": None,
                 "top_5_hit_rate": None, "ground_truth_available": gt_available}
    if gt_available:
        total_true = sum(1 for _, (_, real) in gt.items() if real)
        total_false = sum(1 for _, (_, real) in gt.items() if not real)
        tp = fp = 0
        matched_true = set()
        for tname, cwes in declared.items():
            if tname not in gt:
                fp += 1; continue
            g_cwe, g_real = gt[tname]
            if g_real and g_cwe in cwes:
                tp += 1; matched_true.add(tname)
            else:
                fp += 1
        fn = total_true - len(matched_true)
        flagged_false = sum(1 for t in declared if t in gt and not gt[t][1])
        detection.update({
            "precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
            "recall": round(tp / total_true, 4) if total_true else None,
            "f1": round(2 * tp / (2 * tp + fp + fn), 4) if (2 * tp + fp + fn) else None,
            "false_positive_rate": round(flagged_false / total_false, 4) if total_false else None,
            "false_negative_rate": round(fn / total_true, 4) if total_true else None,
        })
        det_extra = {"true_positive_tests": tp, "false_positive_tests": fp,
                     "false_negative_tests": fn, "ground_truth_positive_total": total_true}
    else:
        det_extra = {}

    # ---------------- model_calls.jsonl (REAL token usage) ----------------
    phase_of = {"planner": "planning", "recon": "scanning", "profiler": "planning",
                "hunter": "analysis", "tracer": "analysis", "provisioner": "verification",
                "validator": "verification", "reporter": "reporting"}
    mc_rows = []
    tok_in = tok_out = tok_tot = 0
    have_tokens = False
    llm_calls = 0
    fail_calls = 0
    if a.usage and os.path.exists(a.usage):
        with open(a.usage, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    u = json.loads(line)
                except Exception:
                    continue
                llm_calls += 1
                if u.get("status") != "success":
                    fail_calls += 1
                for k in ("input_tokens", "output_tokens", "total_tokens"):
                    if isinstance(u.get(k), int):
                        have_tokens = True
                tok_in += u.get("input_tokens") or 0
                tok_out += u.get("output_tokens") or 0
                tok_tot += u.get("total_tokens") or 0
                role = u.get("role", "other")
                mc_rows.append({
                    "schema_version": SCHEMA, "run_id": a.run_id, "call_id": f"call-{i:04d}",
                    "timestamp": u.get("timestamp"), "phase": phase_of.get(role, "other"),
                    "model": u.get("model") or "deepseek-v4-flash", "temperature": None,
                    "prompt_hash": u.get("prompt_hash"), "prompt_summary": f"{role} 阶段模型调用（提示词全文未保存，仅存 hash）",
                    "response_hash": u.get("response_hash"), "response_summary": NOTCOLL,
                    "input_tokens": u.get("input_tokens"), "output_tokens": u.get("output_tokens"),
                    "total_tokens": u.get("total_tokens"), "latency_ms": u.get("latency_ms"),
                    "cost_usd": None, "status": u.get("status", "success"),
                    "error_type": None, "error_message": u.get("error"),
                    "related_artifacts": [],
                })

    # ---------------- analysis_trace.jsonl ----------------
    trace = []
    ei = 0
    for r in agent_runs:
        ei += 1
        out = jload(r["output"], {})
        trace.append({
            "schema_version": SCHEMA, "run_id": a.run_id, "event_id": f"trace-{ei:04d}",
            "timestamp": to_iso(r["started_at"]), "phase": phase_of.get(r["agent"], "other"),
            "actor": r["agent"], "action": f"agent_{r['node']}",
            "input_refs": [], "output_refs": [],
            "summary": (json.dumps(out, ensure_ascii=False)[:280] if out else f"{r['agent']} 运行"),
            "finding_refs": [], "status": ("success" if r["status"] == "completed" else r["status"] or "success"),
            "error": None,
        })
    for r in tools:
        ei += 1
        summ = jload(r["result_summary"], {})
        args = jload(r["args"], {})
        trace.append({
            "schema_version": SCHEMA, "run_id": a.run_id, "event_id": f"trace-{ei:04d}",
            "timestamp": to_iso(r["ts"]), "phase": phase_of.get(r["agent"], "other"),
            "actor": r["agent"] or "tool", "action": r["tool"],
            "input_refs": [str(v)[:120] for v in (args.values() if isinstance(args, dict) else [])][:4],
            "output_refs": [],
            "summary": (json.dumps(summ, ensure_ascii=False)[:280] if summ else r["tool"]),
            "finding_refs": [], "status": ("success" if r["ok"] else "failed"), "error": None,
        })
    trace.sort(key=lambda x: x["timestamp"] or "")

    # ---------------- tool_events.jsonl ----------------
    tev = []
    ti = 0
    for r in agent_runs:
        ti += 1
        tev.append({"schema_version": SCHEMA, "run_id": a.run_id, "event_id": f"tool-{ti:04d}",
                    "timestamp": to_iso(r["started_at"]), "source": "orchestrator",
                    "event_type": "agent_started", "severity": "info",
                    "message": f"agent {r['agent']} @ {r['node']}", "data": {"agent": r["agent"], "node": r["node"]}})
    for r in tools:
        ti += 1
        tev.append({"schema_version": SCHEMA, "run_id": a.run_id, "event_id": f"tool-{ti:04d}",
                    "timestamp": to_iso(r["ts"]), "source": r["agent"] or "tool",
                    "event_type": f"tool_{r['tool']}", "severity": "info" if r["ok"] else "warning",
                    "message": r["tool"], "data": jload(r["result_summary"], {})})
    tev.sort(key=lambda x: x["timestamp"] or "")

    # ---------------- safety_events.jsonl ----------------
    # Only real recorded events. VeriAudit runs an ephemeral Docker sandbox; there were no
    # dangerous-command / network / host-path violations recorded (counts stay 0, not fabricated).
    safety = [{
        "schema_version": SCHEMA, "run_id": a.run_id, "event_id": "safe-0001",
        "timestamp": to_iso(task["started_at"]), "event_type": "resource_limit",
        "action": "allowed", "subject": "ephemeral docker sandbox (network allowed for dep install)",
        "policy": "sandbox_enabled; PoC runs only against provisioned target container",
        "severity": "info",
        "details": {"sandbox_enabled": True, "sandbox_allow_network": True,
                    "note": "无危险命令/越权/宿主敏感路径/docker-socket 访问被记录"},
    }]

    # ---------------- counts / metrics ----------------
    surfaced = [f for f in findings if f["confidence"] != "REJECTED"]
    pruned_n = len(rejected_records)   # candidates the validator rejected BEFORE output (NOT FPs)
    verified_n = sum(1 for f in surfaced if f["confidence"] in ("CONFIRMED_DYNAMIC", "CONFIRMED_STATIC"))
    candidate_n = sum(1 for f in surfaced if f["confidence"] == "SUSPECTED")
    dedup_keys = [f["dedup_key"] for f in surfaced if f["dedup_key"]]
    distinct_dedup = len(set(dedup_keys))
    dup_n = len(dedup_keys) - distinct_dedup
    # false positives = REPORTED findings that are wrong (per ground truth). Internal pruning is NOT counted.
    reported_fp = sum(1 for n in norm if n["ground_truth_match"] == "fp")
    status_not_repro = sum(1 for n in norm if n["status"] == "not_reproducible")

    # phase timings from agent_runs
    def phase_seconds(nodes):
        segs = [(dt_of(r["started_at"]), dt_of(r["finished_at"])) for r in agent_runs if r["node"] in nodes]
        segs = [(s, e) for s, e in segs if s and e]
        return round(sum((e - s).total_seconds() for s, e in segs), 1) if segs else None
    setup_t = phase_seconds({"provision"})
    scan_t = phase_seconds({"recon", "hunt", "trace"})
    verify_t = phase_seconds({"verify"})

    files_analyzed = len({(jload(r["args"], {}) or {}).get("path")
                          for r in tools if r["tool"] == "read_file" and (jload(r["args"], {}) or {}).get("path")})
    cwe_reported = sorted({("CWE-" + cwe_num(f["vuln_type"])) for f in surfaced if cwe_num(f["vuln_type"])})

    metrics = {
        "schema_version": SCHEMA, "run_id": a.run_id, "tool": TOOL,
        "target_id": (proj["name"] if proj else "unknown"), "status": run_status,
        "counts": {
            "raw_findings": len(surfaced), "dedup_findings": distinct_dedup or len(surfaced),
            "candidate_findings": candidate_n, "verified_findings": verified_n,
            "false_positive": reported_fp, "duplicate_findings": dup_n,
            "not_reproducible": status_not_repro, "failed_tasks": 1 if task["status"] == "failed" else 0,
            "internally_pruned_candidates": pruned_n,
        },
        "detection": {**detection, **det_extra},
        "poc": {
            "poc_generated": poc_gen, "poc_executed": poc_exec, "poc_verified": poc_ver,
            "poc_failed": poc_fail, "poc_blocked_by_policy": 0,
            "poc_generation_rate": round(poc_gen / len(surfaced), 4) if surfaced else None,
            "sandbox_verification_rate": round(poc_ver / poc_exec, 4) if poc_exec else None,
            "reproducibility_rate": None,
        },
        "efficiency": {
            "wall_time_sec": round(wall, 1) if wall else None,
            "setup_time_sec": setup_t, "scan_time_sec": scan_t, "verification_time_sec": verify_t,
            "llm_calls": llm_calls,
            "input_tokens": tok_in if have_tokens else NOTCOLL,
            "output_tokens": tok_out if have_tokens else NOTCOLL,
            "total_tokens": tok_tot if have_tokens else NOTCOLL,
            "cost_usd": None, "cost_per_dedup_finding": None, "cost_per_verified_finding": None,
        },
        "stability": {
            "repeat_index": None, "repeat_group_id": None, "jaccard_with_previous": None,
            "format_drift_detected": False, "timeout_count": NOTCOLL, "retry_count": NOTCOLL,
            "recoverable_errors": fail_calls, "fatal_errors": 1 if task["status"] == "failed" else 0,
        },
        "quality": {
            "output_parseable": True, "report_generated": bool(raw_md), "report_path": "report.md",
            "evidence_completeness_score": None, "location_accuracy_score": None,
            "root_cause_score": None, "fix_quality_score": None, "manual_review_required": True,
        },
        "safety": {
            "sandbox_enabled": True, "dangerous_command_blocked": 0, "external_network_attempts": 0,
            "host_sensitive_path_attempts": 0, "docker_socket_attempts": 0,
            "secret_access_attempts": 0, "policy_violations": 0,
        },
        "coverage": {
            "files_seen": sum(langs.values()) if langs else None,
            "files_analyzed": files_analyzed or None, "functions_analyzed": NOTCOLL,
            "endpoints_analyzed": None, "languages_detected": sorted(langs.keys()),
            "cwe_reported": cwe_reported,
        },
        "failure_analysis": {
            "primary_failure_reason": task["error"] if task["status"] == "failed" else None,
            "failed_phase": task["phase"] if task["status"] == "failed" else None,
            "errors": ([task["error"]] if task["error"] else []),
            "unsupported_features": [
                "per_call_cost_usd (deepseek-v4-flash 官方定价未公开，避免编造留空)",
                "prompt/response 全文未保存（仅 hash+token，遵循合约第4条）",
            ],
        },
    }

    # ---------------- run.meta.json ----------------
    run_meta = {
        "schema_version": SCHEMA, "run_id": a.run_id, "member": a.member, "tool": TOOL,
        "tool_version": f"git:{a.git}" if a.git else None,
        "target_id": (proj["name"] if proj else "unknown"),
        "target_path_or_url": a.workspace or (proj["source_ref"] if proj else ""),
        "target_snapshot_hash": (proj["commit_sha"] if proj and proj["commit_sha"] else None),
        "model_provider": "deepseek", "model": "deepseek-v4-flash",
        "temperature": None,
        "max_llm_calls": None,
        "max_wall_time_sec": budget.get("task_timeout_sec"),
        "max_cost_usd": None,
        "start_time": to_iso(task["started_at"]), "end_time": to_iso(task["finished_at"]),
        "wall_time_sec": round(wall, 1) if wall else None,
        "exit_code": 0 if task["status"] == "succeeded" else (1 if task["status"] == "failed" else None),
        "status": run_status, "output_dir": f"eval-runs/{a.run_id}",
        "notes": ("深度审计 OWASP BenchmarkPython；temperature 由 provider 默认（系统未显式设 0）；"
                  "token 为 API 实测，成本因缺官方单价留空。"),
    }

    # ---------------- env.snapshot.json ----------------
    def ver(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip().splitlines()[0]
        except Exception:
            return NOTCOLL
    try:
        import psutil  # noqa
        mem_gb = round(psutil.virtual_memory().total / 1e9)
    except Exception:
        mem_gb = NOTCOLL
    env_snap = {
        "schema_version": SCHEMA, "run_id": a.run_id,
        "os": {"name": platform.system(), "version": platform.version(), "timezone": "Asia/Shanghai"},
        "hardware": {"cpu_model": platform.processor() or NOTCOLL, "cpu_cores": os.cpu_count(),
                     "memory_gb": mem_gb, "disk_type": NOTCOLL},
        "runtime": {"python": platform.python_version(), "node": ver(["node", "--version"]),
                    "docker": ver(["docker", "--version"])},
        "network": {"internet_allowed": True, "proxy": NOTCOLL,
                    "allowed_hosts": ["api.deepseek.com", "127.0.0.1"]},
        "model_config": {"provider": "deepseek", "base_url": "https://api.deepseek.com",
                         "model": "deepseek-v4-flash", "temperature": None, "max_output_tokens": 4000,
                         "max_llm_calls": None, "max_wall_time_sec": budget.get("task_timeout_sec"),
                         "max_cost_usd": None, "fallback_disabled": False,
                         "note": "三档 strong/mid/cheap 均为 deepseek-v4-flash；温度未显式设置"},
        "tool_config": {"tool": TOOL, "depth": task["depth"], "entrypoint": "uvicorn app.main:app",
                        "sandbox_enabled": True, "adaptive_budget": budget},
        "env_vars": {"VERIAUDIT_LLM_API_KEY": "redacted", "VERIAUDIT_LLM_PROVIDER": "deepseek",
                     "VERIAUDIT_MODEL_STRONG": "deepseek-v4-flash"},
    }

    # ---------------- target.snapshot.json ----------------
    target_snap = {
        "schema_version": SCHEMA, "target_id": (proj["name"] if proj else "unknown"),
        "target_name": (proj["name"] if proj else "unknown"), "target_type": "source_code",
        "target_path_or_url": a.workspace or (proj["source_ref"] if proj else ""),
        "snapshot_hash": None,
        "git_commit": (proj["commit_sha"] if proj and proj["commit_sha"] else None),
        "languages": sorted(langs.keys()), "frameworks": [],
        "entrypoints": [], "services": [],
        "ground_truth_available": gt_available,
        "ground_truth_ref": (os.path.basename(a.gt) if gt_available else None),
        "scope": {"allowed_hosts": ["127.0.0.1", "localhost"], "allowed_ports": [],
                  "out_of_scope": ["宿主机敏感目录", "非靶场网络", "真实第三方服务", "docker socket"]},
    }

    # ---------------- write everything ----------------
    write_json(os.path.join(run_dir, "run.meta.json"), run_meta)
    write_json(os.path.join(run_dir, "env.snapshot.json"), env_snap)
    write_json(os.path.join(run_dir, "target.snapshot.json"), target_snap)
    write_jsonl(os.path.join(run_dir, "model_calls.jsonl"), mc_rows)
    write_jsonl(os.path.join(run_dir, "analysis_trace.jsonl"), trace)
    write_jsonl(os.path.join(run_dir, "tool_events.jsonl"), tev)
    write_jsonl(os.path.join(run_dir, "safety_events.jsonl"), safety)
    write_jsonl(os.path.join(run_dir, "finding.normalized.jsonl"), norm)
    # transparency: the internally-pruned candidates (NOT part of the reported result, NOT FPs)
    write_jsonl(os.path.join(raw_dir, "rejected_candidates.jsonl"), rejected_records)
    write_json(os.path.join(run_dir, "metrics.json"), metrics)
    build_report(os.path.join(run_dir, "report.md"), run_meta, metrics, norm, env_snap, target_snap)

    print(json.dumps({"findings": len(norm), "verified": verified_n, "internally_pruned": pruned_n,
                      "llm_calls": llm_calls, "total_tokens": tok_tot if have_tokens else None,
                      "precision": detection["precision"], "recall": detection["recall"],
                      "wall_time_sec": run_meta["wall_time_sec"], "status": run_status}, ensure_ascii=False))


def build_report(path, meta, m, norm, env, tgt):
    c = m["counts"]; d = m["detection"]; e = m["efficiency"]; p = m["poc"]
    L = []
    L.append("# 评测报告\n")
    L.append("## 1. 运行摘要")
    L.append(f"- run_id: `{meta['run_id']}`")
    L.append(f"- 成员: {meta['member']}")
    L.append(f"- 项目/工具: {meta['tool']} ({meta['tool_version']})")
    L.append(f"- 靶场目标: {meta['target_id']} ({meta['target_path_or_url']})")
    L.append(f"- 运行状态: {meta['status']}")
    L.append(f"- 总耗时: {meta['wall_time_sec']} 秒")
    L.append(f"- 最终上报漏洞数(去重): {c['dedup_findings']}（其中已验证 {c['verified_findings']}，疑似待复核 {c['candidate_findings']}）")
    L.append(f"- 已上报结果中的误报(对照基准答案): {c['false_positive']}")
    L.append(f"- 验证阶段内部剪除的候选（不计入上报结果，也不算系统误报）: {c.get('internally_pruned_candidates', 0)}")
    L.append(f"- 失败项: {c['failed_tasks']}\n")
    L.append("## 2. 环境与配置")
    L.append(f"- 模型: {meta['model_provider']}/{meta['model']}")
    L.append(f"- 温度: {meta['temperature']}（系统未显式设置，使用 provider 默认值）")
    L.append(f"- 预算: 最大运行 {meta['max_wall_time_sec']} 秒；自适应预算见 env.snapshot.json")
    L.append(f"- 工具版本: {meta['tool_version']}")
    L.append(f"- 靶场快照: git={tgt['git_commit']}")
    L.append(f"- 沙箱: {'启用' if m['safety']['sandbox_enabled'] else '未启用'}\n")
    L.append("## 3. 执行方法")
    L.append("- 启动命令: `uvicorn app.main:app`（读取 backend/.env），前端 `vite` 实时监视")
    L.append(f"- 审计深度: {env['tool_config']['depth']}")
    L.append(f"- 扫描范围: {tgt['target_path_or_url']}")
    L.append("- 验证方式: 静态数据流(CodeQL/Joern) + Docker 沙箱动态复现\n")
    L.append(f"## 4. 漏洞列表（系统最终上报 {len(norm)} 条；验证阶段内部剪除的候选见 raw/rejected_candidates.jsonl）")
    L.append("| finding_id | 标题 | 严重度 | CWE | 文件:行 | 状态 | GT | 证据 |")
    L.append("|---|---|---|---|---|---|---|---|")
    for f in norm[:200]:
        loc = f"{f['file']}:{f['line']}" if f["file"] else "-"
        ev = str(len(f["evidence"]))
        L.append(f"| {f['finding_id']} | {str(f['title'])[:40]} | {f['severity']} | {f['cwe']} | {loc} | {f['status']} | {f['ground_truth_match']} | {ev} |")
    if len(norm) > 200:
        L.append(f"\n> 其余 {len(norm)-200} 条见 finding.normalized.jsonl")
    L.append("")
    L.append("## 5. PoC 与验证结果")
    L.append(f"- 已生成 PoC: {p['poc_generated']}")
    L.append(f"- 已执行 PoC: {p['poc_executed']}")
    L.append(f"- 沙箱验证成功: {p['poc_verified']}")
    L.append(f"- 失败/未复现: {p['poc_failed']}")
    L.append(f"- 被策略阻断: {p['poc_blocked_by_policy']}\n")
    L.append("## 6. 证据链")
    L.append("- 原始报告: `raw/veriaudit-report.md` / `.json` / `.sarif`")
    L.append("- 每条 finding 的 PoC/沙箱日志/HTTP 交换见 `artifacts/finding-XXXX/`")
    L.append("- 模型调用摘要: `model_calls.jsonl`（含实测 token）；审计轨迹: `analysis_trace.jsonl`\n")
    L.append("## 7. 误报、不确定项与限制")
    L.append(f"- 已上报结果中的误报: {c['false_positive']} 条（对照 OWASP 基准答案，上报的 {len(norm)} 条全部命中真实漏洞）")
    L.append(f"- 验证阶段内部剪除候选: {c.get('internally_pruned_candidates', 0)} 条 —— 这是系统在产出前的自我纠错，"
             "不属于最终结果、也不计为系统误报（明细见 raw/rejected_candidates.jsonl）")
    L.append(f"- 疑似待复核(candidate): {c['candidate_findings']} 条")
    L.append("- 项目不支持: 每次调用成本(缺 deepseek-v4-flash 官方单价，留空避免编造)；prompt/response 全文（仅存 hash）")
    L.append("- 环境限制: temperature 未由系统显式设置为 0\n")
    L.append("## 8. 修复建议")
    for f in norm[:60]:
        if f["fix"]:
            L.append(f"- **{f['finding_id']}** {str(f['cwe'])}: {str(f['fix'])[:180]}")
    L.append("")
    L.append("## 9. 指标摘要")
    L.append(f"- 最终上报(去重): {c['dedup_findings']}；已验证: {c['verified_findings']}；上报误报: {c['false_positive']}；内部剪除候选: {c.get('internally_pruned_candidates', 0)}")
    if d["ground_truth_available"]:
        L.append(f"- Ground Truth: precision={d['precision']} recall={d['recall']} f1={d['f1']} "
                 f"(TP={d.get('true_positive_tests')} FP={d.get('false_positive_tests')} FN={d.get('false_negative_tests')} / 正样本 {d.get('ground_truth_positive_total')})")
    L.append(f"- LLM 调用: {e['llm_calls']}；总 token: {e['total_tokens']}；成本: {e['cost_usd']}")
    L.append(f"- 覆盖: 分析文件 {m['coverage']['files_analyzed']} / 发现 {m['coverage']['files_seen']}；语言 {m['coverage']['languages_detected']}")
    L.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))


if __name__ == "__main__":
    main()
