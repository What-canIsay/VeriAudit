"""LLM gateway over LiteLLM with model tiering and safe degradation.

- Cloud mode: routes to the configured provider/model via LiteLLM using an API key.
- Mock mode (no key) OR any runtime error: callers fall back to the deterministic
  analysis path, so the whole pipeline always completes.

The gateway exposes two shapes used by the orchestrator:
  * judge(role, system, user)  -> parsed JSON dict (LLM-as-judge / structured triage)
  * agentic(role, system, user, tools, dispatch, max_steps) -> final text + trace
"""
from __future__ import annotations

import json
import re
from typing import Callable, Dict, List, Optional, Tuple

from ..config import settings

try:  # litellm is optional at import time
    import litellm  # type: ignore
    litellm.drop_params = True
    litellm.suppress_debug_info = True
    _HAS_LITELLM = True
except Exception:  # pragma: no cover
    _HAS_LITELLM = False


class LLMGateway:
    def __init__(self) -> None:
        self.enabled = (not settings.mock_mode) and _HAS_LITELLM
        self.last_error: Optional[str] = None

    def _model(self, role: str) -> str:
        m = settings.role_model(role)
        if "/" in m or settings.llm_provider in ("openai",):
            return m if "/" in m else m  # openai models used bare
        return f"{settings.llm_provider}/{m}"

    def _call(self, role: str, messages: List[dict],
              tools: Optional[List[dict]] = None) -> Optional[object]:
        if not self.enabled:
            return None
        kwargs: Dict[str, object] = {
            "model": self._model(role),
            "messages": messages,
            "api_key": settings.llm_api_key,
            "max_tokens": 4000,
        }
        if settings.llm_api_base:
            kwargs["api_base"] = settings.llm_api_base
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        try:
            resp = litellm.completion(**kwargs)  # type: ignore
            return resp.choices[0].message
        except Exception as e:  # degrade
            self.last_error = str(e)[:300]
            return None

    def judge(self, role: str, system: str, user: str) -> Optional[dict]:
        msg = self._call(role, [
            {"role": "system", "content": system + "\n\n只输出一个 JSON 对象，不要解释、不要代码块围栏。"},
            {"role": "user", "content": user},
        ])
        if msg is None:
            return None
        return _parse_json(getattr(msg, "content", "") or "")

    def agentic(self, role: str, system: str, user: str,
                tools: List[dict], dispatch: Callable[[str, dict], dict],
                on_tool: Optional[Callable[[str, dict, dict], None]] = None,
                max_steps: int = 6) -> Tuple[Optional[str], List[dict]]:
        """Bounded tool-calling loop. Returns (final_text, trace)."""
        if not self.enabled:
            return None, []
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        trace: List[dict] = []
        for _ in range(max_steps):
            msg = self._call(role, messages, tools=tools)
            if msg is None:
                break
            tool_calls = getattr(msg, "tool_calls", None) or []
            if not tool_calls:
                return (getattr(msg, "content", "") or ""), trace
            messages.append({"role": "assistant", "content": getattr(msg, "content", "") or "",
                             "tool_calls": [tc.model_dump() if hasattr(tc, "model_dump") else tc
                                            for tc in tool_calls]})
            for tc in tool_calls:
                fn = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except Exception:
                    args = {}
                result = dispatch(fn, args)
                if on_tool:
                    on_tool(fn, args, result)
                trace.append({"tool": fn, "args": args})
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": json.dumps(result, ensure_ascii=False)[:6000]})
        return None, trace


def _parse_json(text: str) -> Optional[dict]:
    text = text.strip()
    text = re.sub(r"^```(json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{.*\}", text, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return None
    return None


llm = LLMGateway()
