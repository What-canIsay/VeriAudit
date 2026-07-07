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
