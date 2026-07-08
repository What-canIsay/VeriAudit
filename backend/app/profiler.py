"""Project profiler (规模/复杂度评估模块).

Runs FIRST, before the audit pipeline, and derives every runtime budget/limit from
cheap deterministic metrics of the target project (file count, LOC, entrypoints,
languages, dependencies, whether it needs a build toolchain / database / multiple
services). The idea: a 5-file Flask sample and a 400-file polyglot app should NOT
share the same step caps and timeouts — small projects finish fast and cheap, large
projects get enough budget to actually complete their work instead of being cut off
mid-task (the root cause of the "hunter produced no candidates / provisioner stopped
mid-build" failures).

Everything here is heuristic but bounded and inspectable; the computed budget is
surfaced to the UI so a human can see WHY a given project got its limits.

assess(root, depth) -> (profile: dict, budget: dict)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Tuple

from . import analysis
from .config import settings

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
              "build", ".idea", ".vscode", "vendor", "target", ".next"}

# ceilings for adaptive scaling (floors come from settings.*)
_CEIL = {
    "llm_hunt_steps": 40,
    "max_candidates": 120,
    "max_verify": 60,
    "llm_triage_limit": 40,
    "provisioner_max_steps": 48,
    "provisioner_timeout_sec": 1800,
    "provisioner_cmd_timeout_sec": 600,
    "llm_timeout_sec": 180,
    "task_timeout_sec": 7200,
}

# manifests / files that imply a heavy build toolchain is needed to stand the app up
_BUILD_MARKERS = ("go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "Cargo.toml",
                  "Makefile", "CMakeLists.txt", "Dockerfile", "composer.json")
_DB_DRIVERS = ("mysql", "mysqli", "pymysql", "psycopg", "postgres", "sqlite", "sqlalchemy",
               "mongoose", "mongodb", "redis", "pdo", "sequelize", "prisma", "knex", "gorm")
_COMPOSE_FILES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


def _scan_tree(root: Path) -> Dict:
    """Bounded walk (skips vendor/node_modules/etc.) to detect build markers and .sql
    files ANYWHERE in the tree — not just at the repo root (e.g. backend/composer.json,
    db/schema.sql)."""
    build_markers = {m.lower() for m in _BUILD_MARKERS}
    has_build = has_sql = False
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            seen += 1
            low = fn.lower()
            if low in build_markers:
                has_build = True
            elif low.endswith(".sql"):
                has_sql = True
        if seen > 8000 or (has_build and has_sql):
            break
    return {"has_build": has_build, "has_sql": has_sql}


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def _scale(t: float, lo: float, hi: float) -> int:
    """Linear interpolate lo..hi by t∈[0,1], rounded to int."""
    return int(round(lo + (hi - lo) * _clamp(t)))


def _gather(root: Path) -> Dict:
    n_files = 0
    loc = 0
    langs: Dict[str, int] = {}
    for p, lang in analysis.iter_source_files(root):
        n_files += 1
        langs[lang] = langs.get(lang, 0) + 1
        try:
            loc += analysis.read_text(p).count("\n")
        except Exception:
            pass

    stack = analysis.detect_stack(root)
    deps: list = []
    for lst in (stack.get("deps") or {}).values():
        deps.extend(lst)
    n_deps = len(deps)
    deps_blob = " ".join(deps).lower() + " " + " ".join(stack.get("frameworks") or []).lower()

    try:
        n_entrypoints = len(analysis.find_entrypoints(root))
    except Exception:
        n_entrypoints = 0

    tree = _scan_tree(root)
    has_compose = any((root / f).exists() for f in _COMPOSE_FILES)
    needs_build = tree["has_build"]
    # db signal: .sql files present, or a db driver appears in deps/frameworks, or compose
    has_db = tree["has_sql"] or has_compose or any(d in deps_blob for d in _DB_DRIVERS)
    polyglot = sum(1 for c in langs.values() if c >= 2) >= 3

    return {
        "n_files": n_files, "loc": loc, "languages": langs, "n_langs": len(langs),
        "n_entrypoints": n_entrypoints, "n_deps": n_deps,
        "has_compose": has_compose, "needs_build": needs_build, "has_db": has_db,
        "polyglot": polyglot,
    }


def _tier(t: float) -> str:
    if t < 0.2:
        return "small"
    if t < 0.45:
        return "medium"
    if t < 0.75:
        return "large"
    return "xlarge"


def assess(root: Path, depth: str) -> Tuple[Dict, Dict]:
    try:
        m = _gather(root)
    except Exception:
        m = {"n_files": 0, "loc": 0, "languages": {}, "n_langs": 0, "n_entrypoints": 0,
             "n_deps": 0, "has_compose": False, "needs_build": False, "has_db": False,
             "polyglot": False}

    # --- audit-surface complexity t (drives hunt / verify budgets) ---
    files_t = _clamp(m["n_files"] / 400.0)
    ep_t = _clamp(m["n_entrypoints"] / 200.0)
    loc_t = _clamp(m["loc"] / 60000.0)
    t = _clamp(0.45 * files_t + 0.30 * ep_t + 0.25 * loc_t + (0.10 if m["polyglot"] else 0.0))

    # --- provisioning complexity pt (drives setup budgets) ---
    pt = 0.0
    if m["needs_build"]:
        pt += 0.35
    if m["has_db"]:
        pt += 0.30
    if m["has_compose"]:
        pt += 0.20
    if m["polyglot"]:
        pt += 0.15
    pt += 0.20 * _clamp(m["n_deps"] / 80.0)
    pt = _clamp(max(pt, 0.30 * t))

    fl = settings  # floors
    budget: Dict = {
        # discovery
        "llm_hunt_steps": _scale(t, fl.llm_hunt_steps, _CEIL["llm_hunt_steps"]),
        "max_candidates": _scale(t, fl.max_candidates, _CEIL["max_candidates"]),
        # verification
        "max_verify": _scale(t, fl.max_verify, _CEIL["max_verify"]),
        "llm_triage_limit": _scale(t, fl.llm_triage_limit, _CEIL["llm_triage_limit"]),
        "dynamic_verification": depth in ("standard", "deep") and fl.enable_sandbox,
        "llm_augment": depth in ("standard", "deep"),
        # provisioning
        "provisioner_max_steps": _scale(pt, fl.provisioner_max_steps, _CEIL["provisioner_max_steps"]),
        "provisioner_timeout_sec": _scale(pt, fl.provisioner_timeout_sec, _CEIL["provisioner_timeout_sec"]),
        "provisioner_cmd_timeout_sec": _scale(
            pt if m["needs_build"] else pt * 0.5,
            fl.provisioner_cmd_timeout_sec, _CEIL["provisioner_cmd_timeout_sec"]),
        # llm request
        "llm_timeout_sec": _scale(t, fl.llm_timeout_sec, _CEIL["llm_timeout_sec"]),
        "llm_num_retries": fl.llm_num_retries if t < 0.6 else fl.llm_num_retries + 1,
    }

    # --- overall task wall-clock: must encompass every phase we just budgeted ---
    hunt_alloc = budget["llm_hunt_steps"] * 12
    verify_alloc = budget["max_verify"] * 15
    provision_alloc = budget["provisioner_timeout_sec"] if depth == "deep" else 0
    task_timeout = 600 + hunt_alloc + verify_alloc + provision_alloc + 300
    budget["task_timeout_sec"] = int(max(fl.task_timeout_sec,
                                         min(_CEIL["task_timeout_sec"], task_timeout)))

    if not getattr(settings, "enable_adaptive_budget", True):
        budget = _static_budget(depth)

    tier = _tier(t)
    profile = {
        "tier": tier, "complexity": round(t, 2), "provision_complexity": round(pt, 2),
        "metrics": m,
        "rationale": (f"规模档位 {tier}：{m['n_files']} 文件 / {m['loc']} 行 / "
                      f"{m['n_entrypoints']} 入口点 / {m['n_langs']} 种语言 / {m['n_deps']} 依赖"
                      + ("；需要构建工具链" if m["needs_build"] else "")
                      + ("；含数据库" if m["has_db"] else "")
                      + ("；多服务(compose)" if m["has_compose"] else "")
                      + ("；多语言混合" if m["polyglot"] else "") + "。"),
    }
    return profile, budget


def _static_budget(depth: str) -> Dict:
    """Fallback: the old fixed limits (adaptive budgeting disabled)."""
    return {
        "llm_hunt_steps": settings.llm_hunt_steps,
        "max_candidates": settings.max_candidates,
        "max_verify": settings.max_verify if depth != "fast" else max(6, settings.max_verify // 2),
        "llm_triage_limit": settings.llm_triage_limit,
        "dynamic_verification": depth in ("standard", "deep") and settings.enable_sandbox,
        "llm_augment": depth in ("standard", "deep"),
        "provisioner_max_steps": settings.provisioner_max_steps,
        "provisioner_timeout_sec": settings.provisioner_timeout_sec,
        "provisioner_cmd_timeout_sec": settings.provisioner_cmd_timeout_sec,
        "llm_timeout_sec": settings.llm_timeout_sec,
        "llm_num_retries": settings.llm_num_retries,
        "task_timeout_sec": settings.task_timeout_sec,
    }
