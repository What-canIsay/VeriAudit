"""LLM gateway over LiteLLM with model tiering and safe degradation.

- Cloud mode: routes to the configured provider/model via LiteLLM using an API key.
- Mock mode (no key) OR any runtime error: callers fall back to the deterministic
  analysis path, so the whole pipeline always completes.

Surfaces used by the orchestrator:
  * judge_ex(role, system, user)      -> (parsed_json | None, reasoning, content)
  * agentic(role, ..., on_step, on_tool) -> (final_text | None, trace)
Both expose the model's REASONING (chain-of-thought / reasoning_content, when the
provider returns it, e.g. DeepSeek) so it can be streamed to the UI.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from ..config import settings

try:
    import litellm  # type: ignore
    litellm.drop_params = True
    litellm.suppress_debug_info = True
    _HAS_LITELLM = True
except Exception:  # pragma: no cover
    _HAS_LITELLM = False


# --- optional audit sink: record REAL per-call token usage from the provider response.
# Enabled only when VERIAUDIT_LLM_USAGE_LOG points at a file. Append-only JSONL; never
# raises into the request path. Used to build eval datasets from measured (not guessed) data.
_USAGE_LOCK = threading.Lock()


def _record_usage(role: str, messages: List[dict], resp, content: str,
                  latency_ms: int, status: str, error: Optional[str]) -> None:
    path = os.environ.get("VERIAUDIT_LLM_USAGE_LOG")
    if not path:
        return
    try:
        usage = getattr(resp, "usage", None) if resp is not None else None
        def _u(k):
            v = getattr(usage, k, None) if usage is not None else None
            if v is None and isinstance(usage, dict):
                v = usage.get(k)
            return int(v) if isinstance(v, (int, float)) else None
        prompt_text = json.dumps(messages, ensure_ascii=False)
        rec = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "role": role,
            "model": getattr(resp, "model", None),
            "prompt_hash": "sha256:" + hashlib.sha256(prompt_text.encode("utf-8")).hexdigest(),
            "response_hash": ("sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()) if content else None,
            "input_tokens": _u("prompt_tokens"),
            "output_tokens": _u("completion_tokens"),
            "total_tokens": _u("total_tokens"),
            "latency_ms": latency_ms,
            "status": status,
            "error": error,
        }
        line = json.dumps(rec, ensure_ascii=False)
        with _USAGE_LOCK:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass  # telemetry must never break the audit


# in-loop resilience: a single transient LLM failure (timeout / 5xx / rate limit) must not
# abort a long agentic session. Retry the step a few times before giving up.
_STEP_RETRIES = 2
_STEP_RETRY_SLEEP = 2.0


class LLMGateway:
    def __init__(self) -> None:
        self.enabled = (not settings.mock_mode) and _HAS_LITELLM
        self.last_error: Optional[str] = None

    def _model(self, role: str) -> str:
        m = settings.role_model(role)
        if "/" in m or settings.llm_provider == "openai":
            return m
        return f"{settings.llm_provider}/{m}"

    @staticmethod
    def _reasoning(msg) -> Optional[str]:
        r = getattr(msg, "reasoning_content", None)
        if not r:
            psf = getattr(msg, "provider_specific_fields", None)
            if isinstance(psf, dict):
                r = psf.get("reasoning_content")
        return r or None

    def _call(self, role: str, messages: List[dict],
              tools: Optional[List[dict]] = None,
              timeout: Optional[int] = None, num_retries: Optional[int] = None):
        if not self.enabled:
            return None
        kwargs: Dict[str, object] = {
            "model": self._model(role),
            "messages": messages,
            "api_key": settings.llm_api_key,
            "max_tokens": 4000,
            "timeout": timeout or settings.llm_timeout_sec,
            "num_retries": settings.llm_num_retries if num_retries is None else num_retries,
        }
        if settings.llm_api_base:
            kwargs["api_base"] = settings.llm_api_base
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        t0 = time.monotonic()
        try:
            resp = litellm.completion(**kwargs)  # type: ignore
            msg = resp.choices[0].message
            _record_usage(role, messages, resp, getattr(msg, "content", "") or "",
                          int((time.monotonic() - t0) * 1000), "success", None)
            return msg
        except Exception as e:
            self.last_error = str(e)[:300]
            _record_usage(role, messages, None, "",
                          int((time.monotonic() - t0) * 1000), "failed", str(e)[:300])
            return None

    def judge_ex(self, role: str, system: str, user: str,
                 timeout: Optional[int] = None, num_retries: Optional[int] = None
                 ) -> Tuple[Optional[dict], Optional[str], Optional[str]]:
        msg = self._call(role, [
            {"role": "system", "content": system + "\n\n只输出一个 JSON 对象，不要解释、不要代码块围栏。"},
            {"role": "user", "content": user},
        ], timeout=timeout, num_retries=num_retries)
        if msg is None:
            return None, None, None
        content = getattr(msg, "content", "") or ""
        return _parse_json(content), self._reasoning(msg), content

    def judge(self, role: str, system: str, user: str) -> Optional[dict]:
        return self.judge_ex(role, system, user)[0]

    def agentic(self, role: str, system: str, user: str,
                tools: List[dict], dispatch: Callable[[str, dict], dict],
                on_tool: Optional[Callable[[str, dict, dict], None]] = None,
                on_step: Optional[Callable[[Optional[str], str, List[str]], None]] = None,
                max_steps: int = 10,
                stop_tools: Optional[set] = None,
                finalize_hint: Optional[str] = None,
                finalize_at: int = 2,
                timeout: Optional[int] = None,
                num_retries: Optional[int] = None,
                extend_when: Optional[Callable[[], bool]] = None,
                extend_factor: float = 1.0,
                extend_hard_cap: int = 0,
                must_produce: Optional[Callable[[], bool]] = None,
                harvest_prompt: Optional[str] = None,
                max_finalize_nudges: int = 2,
                checkpoint: Optional[Callable[[], bool]] = None) -> Tuple[Optional[str], List[dict]]:
        """Bounded tool-calling loop where the MODEL drives tool use.

        on_step(reasoning, content, tool_names) fires once per model turn so the UI
        can show what the agent is thinking and which tools it chose.

        finalize_hint: when only `finalize_at` steps remain, this message is injected
        ONCE so the model stops exploring and emits its conclusions (report_candidate /
        mark_ready / give_up) BEFORE the loop is cut off. This fixes the failure where
        the model kept exploring until step exhaustion and never produced any output.

        extend_when/extend_factor/extend_hard_cap: if the step budget is about to run out
        and extend_when() reports the session is "promising" (e.g. mid-reproduction), the
        cap is raised ONCE to ceil(max_steps*extend_factor) (bounded by extend_hard_cap),
        so a nearly-done session isn't cut off. Fires at most once.

        must_produce/harvest_prompt/max_finalize_nudges: for agents whose ENTIRE output is
        side-effects via tool calls (the Hunter's report_candidate) rather than the return
        value. If must_produce() is still False when the model tries to end — either by
        returning a tool-less prose turn OR by exhausting the step budget — we inject
        harvest_prompt and grant an extra turn (up to max_finalize_nudges) so the model
        converts what it already found into tool calls, WITH full exploration context
        intact. This fixes the observed failure where the Hunter examines 100+ files yet
        commits zero candidates and the whole hunt is discarded.
        """
        if not self.enabled:
            return None, []
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        trace: List[dict] = []
        hinted = False
        extended = False
        harvested = 0
        cap = max_steps
        i = 0
        while i < cap:
            # cooperative pause/cancel: blocks while paused, stops the loop on cancel.
            if checkpoint is not None and not checkpoint():
                return None, trace
            # transient LLM failures (timeout / 5xx / rate limit) must not abort a long
            # session — retry the step a few times before giving up.
            msg = None
            for _attempt in range(_STEP_RETRIES + 1):
                msg = self._call(role, messages, tools=tools, timeout=timeout, num_retries=num_retries)
                if msg is not None:
                    break
                if _attempt < _STEP_RETRIES:
                    time.sleep(_STEP_RETRY_SLEEP * (_attempt + 1))
            if msg is None:
                break
            reasoning = self._reasoning(msg)
            content = getattr(msg, "content", "") or ""
            tool_calls = getattr(msg, "tool_calls", None) or []
            if on_step:
                on_step(reasoning, content, [tc.function.name for tc in tool_calls])
            if not tool_calls:
                # model tried to end with prose. If it still owes tool output, don't discard
                # its findings — nudge it to commit them (report_candidate) and continue.
                if must_produce and not must_produce() and harvested < max_finalize_nudges:
                    messages.append({"role": "assistant", "content": content})
                    messages.append({"role": "user", "content": harvest_prompt or finalize_hint or
                                     "请立即用工具登记你的结论，不要只用文字叙述。"})
                    harvested += 1
                    i += 1
                    continue
                return content, trace
            messages.append({"role": "assistant", "content": content,
                             "tool_calls": [tc.model_dump() if hasattr(tc, "model_dump") else tc
                                            for tc in tool_calls]})
            for tc in tool_calls:
                fn = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except Exception:
                    args = {}
                # a single malformed tool call must never crash the whole audit — surface the
                # error back to the model as a tool result so it can adjust and continue.
                try:
                    result = dispatch(fn, args)
                except Exception as e:
                    result = {"error": f"tool '{fn}' failed: {type(e).__name__}: {str(e)[:200]}"}
                if on_tool:
                    on_tool(fn, args, result)
                trace.append({"tool": fn, "args": args})
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": json.dumps(result, ensure_ascii=False)[:6000]})
            if stop_tools and any(tc.function.name in stop_tools for tc in tool_calls):
                return None, trace   # terminal tool called — stop early (saves tokens)
            remaining = cap - i - 1
            # about to run out but the session looks close to done → extend once
            if (remaining <= 0 and not extended and extend_factor > 1.0
                    and extend_when and extend_when()):
                new_cap = int(math.ceil(max_steps * extend_factor))
                if extend_hard_cap:
                    new_cap = min(new_cap, extend_hard_cap)
                if new_cap > cap:
                    cap = new_cap
                    extended = True
                    hinted = False   # re-arm the finalize nudge for the extended window
            # steps running low: force the model to converge/report on its next turn
            if finalize_hint and not hinted and remaining <= finalize_at:
                messages.append({"role": "user", "content": finalize_hint})
                hinted = True
            # guaranteed harvest tail: budget exhausted but the model still owes tool output
            # (e.g. explored the whole project yet committed zero candidates) → grant a
            # dedicated turn to commit its findings, bounded by max_finalize_nudges.
            if (remaining <= 0 and must_produce and not must_produce()
                    and harvested < max_finalize_nudges):
                cap += 1
                messages.append({"role": "user", "content": harvest_prompt or finalize_hint or
                                 "步数已尽，请现在只用工具登记你已发现的每个候选，不要再探索。"})
                harvested += 1
            i += 1
        return None, trace


def _parse_json(text: str) -> Optional[dict]:
    text = (text or "").strip()
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
