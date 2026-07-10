"""CVSS v3.1 base score computation (from vector) + severity level mapping."""
from __future__ import annotations

import math
from typing import Dict

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(x: float) -> float:
    return math.ceil(x * 10) / 10.0


def score_from_vector(vector: str) -> Dict[str, object]:
    try:
        parts = dict(p.split(":") for p in vector.split("/") if ":" in p and not p.startswith("CVSS"))
        scope_changed = parts.get("S", "U") == "C"
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        ui = _UI[parts["UI"]]
        pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]

        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        expl = 8.22 * av * ac * pr * ui
        if impact <= 0:
            base = 0.0
        elif scope_changed:
            base = _roundup(min(1.08 * (impact + expl), 10))
        else:
            base = _roundup(min(impact + expl, 10))
    except Exception:
        base = 5.0
    return {"score": base, "level": level_for(base), "vector": vector}


def level_for(score: float) -> str:
    if score <= 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


# --------------------------------------------------------------------------- #
# CVSS v3.1 vector validation + human-readable decoding (for the finding detail + report).
# --------------------------------------------------------------------------- #
_METRIC_LABELS = {
    "AV": ("攻击途径 (Attack Vector)", {"N": "网络 (Network)", "A": "相邻网络 (Adjacent)",
                                        "L": "本地 (Local)", "P": "物理 (Physical)"}),
    "AC": ("攻击复杂度 (Attack Complexity)", {"L": "低 (Low)", "H": "高 (High)"}),
    "PR": ("所需权限 (Privileges Required)", {"N": "无 (None)", "L": "低 (Low)", "H": "高 (High)"}),
    "UI": ("用户交互 (User Interaction)", {"N": "不需要 (None)", "R": "需要 (Required)"}),
    "S": ("影响范围 (Scope)", {"U": "不变 (Unchanged)", "C": "改变 (Changed)"}),
    "C": ("机密性影响 (Confidentiality)", {"H": "高 (High)", "L": "低 (Low)", "N": "无 (None)"}),
    "I": ("完整性影响 (Integrity)", {"H": "高 (High)", "L": "低 (Low)", "N": "无 (None)"}),
    "A": ("可用性影响 (Availability)", {"H": "高 (High)", "L": "低 (Low)", "N": "无 (None)"}),
}
_REQUIRED = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def _parse_vector(vector: str) -> Dict[str, str]:
    return dict(p.split(":", 1) for p in (vector or "").split("/") if ":" in p and not p.startswith("CVSS"))


def valid_cvss(vector) -> bool:
    """True if the string is a well-formed CVSS v3.x base vector (all 8 base metrics present
    with legal values). Used to accept a model-produced per-instance vector or fall back."""
    if not isinstance(vector, str):
        return False
    parts = _parse_vector(vector)
    return all(m in parts and parts[m] in _METRIC_LABELS[m][1] for m in _REQUIRED)


def explain_vector(vector: str) -> Dict[str, object]:
    """Decode a CVSS vector into a labelled per-metric breakdown + score/level, so the UI and
    report can EXPLAIN why a finding got its severity."""
    parts = _parse_vector(vector)
    metrics = []
    for m in _REQUIRED:
        v = parts.get(m)
        label, vals = _METRIC_LABELS[m]
        metrics.append({"metric": m, "label": label, "value": v or "?",
                        "value_label": vals.get(v, "未知")})
    sev = score_from_vector(vector)
    return {"vector": vector, "score": sev["score"], "level": sev["level"], "metrics": metrics}
