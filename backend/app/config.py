"""Global configuration (env-driven).

VeriAudit is designed to run on a clean machine with zero infra:
- SQLite by default (swap to Postgres via DATABASE_URL)
- Single-process asyncio orchestration (no Celery required for MVP)
- Mock LLM mode when no API key is configured (so the whole pipeline runs offline)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/
DATA_DIR = BASE_DIR / "_data"
WORKSPACE_DIR = DATA_DIR / "workspaces"
ARTIFACT_DIR = DATA_DIR / "artifacts"

for _d in (DATA_DIR, WORKSPACE_DIR, ARTIFACT_DIR):
    _d.mkdir(parents=True, exist_ok=True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VERIAUDIT_", env_file=".env", extra="ignore")

    # --- storage ---
    database_url: str = f"sqlite:///{(DATA_DIR / 'veriaudit.db').as_posix()}"

    # --- server ---
    cors_origins: str = "*"

    # --- LLM gateway (LiteLLM) ---
    # If no api_key is set for the active provider, VeriAudit runs in MOCK mode:
    # the full agent pipeline executes with a deterministic offline model so the
    # system is demonstrable without any cloud credentials.
    llm_provider: str = "openai"          # any LiteLLM-compatible provider label
    llm_api_key: str = ""                 # cloud API key (empty => mock mode)
    llm_api_base: str = ""                # optional custom base url / proxy

    # model tiering per agent role (LiteLLM model strings)
    model_strong: str = "claude-opus-4-8"   # hunter / tracer / validator
    model_mid: str = "claude-opus-4-8"       # planner
    model_cheap: str = "claude-haiku-4-5"    # recon / reporter

    # --- budget guardrails ---
    max_agent_steps: int = 12             # max tool-loop iterations per agent node
    max_candidates: int = 40              # cap candidates per task
    max_verify: int = 20                  # cap validations per task
    task_timeout_sec: int = 1800

    # --- sandbox ---
    enable_sandbox: bool = True           # attempt docker PoC verification if available
    sandbox_image_prefix: str = "veriaudit-sandbox"
    sandbox_timeout_sec: int = 60

    # --- external scanners (graceful degradation if missing) ---
    enable_semgrep: bool = True

    @property
    def mock_mode(self) -> bool:
        return not bool(self.llm_api_key.strip())

    @property
    def cors_list(self):
        if self.cors_origins.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def role_model(self, role: str) -> str:
        mapping: Dict[str, str] = {
            "planner": self.model_mid,
            "recon": self.model_cheap,
            "hunter": self.model_strong,
            "tracer": self.model_strong,
            "validator": self.model_strong,
            "reporter": self.model_cheap,
        }
        return mapping.get(role, self.model_strong)


settings = Settings()
