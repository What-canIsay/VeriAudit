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
    llm_timeout_sec: int = 90                # per-request timeout (avoid hangs)
    llm_num_retries: int = 1                 # bounded retries

    # --- budget guardrails (economy: bound token spend of an LLM-driven run) ---
    # When on, a profiler (app/profiler.py) sizes the target project up front and
    # scales EVERY limit below to its scale/complexity. The values below then act as
    # per-limit FLOORS (small projects) with ceilings defined in the profiler.
    enable_adaptive_budget: bool = True
    llm_hunt_steps: int = 16              # max tool-calling steps for the LLM-driven hunt
    llm_triage_limit: int = 16            # max candidates the LLM validator judges (rest heuristic)
    # agentic validation: for worthy candidates the Validator reads cross-file context
    # + drives dynamic tools (sqlmap/nuclei/runtime debugging) against the standing app
    # to precisely CONFIRM/reproduce. Bounded like the hunt loop to keep token spend sane.
    enable_agentic_verify: bool = True
    # True  = agentic-first: try the tool-driven agentic verify for every eligible
    #         candidate, fall back to the legacy one-shot judge only when it fails.
    # False = static-first (legacy default): use the one-shot judge, escalate to agentic
    #         only for high/critical + reproducible candidates.
    validator_agentic_first: bool = True
    # Whether the AGENTIC_VERIFY_LIMIT quota applies at all. Default OFF → no quota:
    # every eligible candidate gets the agentic verify (thorough, but higher token cost).
    # Turn ON to cap agentic verifications at agentic_verify_limit (token guardrail).
    enable_agentic_verify_limit: bool = False
    agentic_verify_limit: int = 3         # max candidates that get the heavy agentic verify (floor; only when the quota is enabled)
    # per-candidate agentic step budget = base(B) + additive(rank/class/auth/taint).
    # validator_steps is the BASE floor B (project-scale derived in the profiler).
    validator_steps: int = 12             # base step floor B
    validator_step_add_max: int = 12      # cap on the additive part → planned ∈ [B, B+add_max]
    validator_step_extension: float = 1.5  # one-time extension multiplier for a "promising" session
    validator_step_hard_cap: int = 40     # absolute per-candidate step ceiling (safety)
    # Provisioner PREHEAT: after the app is up, an LLM-driven, project-specific session
    # prepares a reusable verification substrate (test accounts, logged-in sessions per
    # role, seeded data, a memo) so per-candidate verification starts warm. Subsumes the
    # old provisioner_llm_enrich DB-seeding.
    enable_provisioner_preheat: bool = True
    preheat_max_steps: int = 14           # preheat tool-step floor (scaled in profiler)
    max_agent_steps: int = 12             # generic per-agent loop cap
    max_candidates: int = 60              # cap candidates per task
    max_verify: int = 30                  # cap validations per task
    task_timeout_sec: int = 1800

    # --- sandbox ---
    enable_sandbox: bool = True           # attempt docker PoC verification if available
    sandbox_image_prefix: str = "veriaudit-sandbox"
    sandbox_timeout_sec: int = 60         # exploit request window
    sandbox_build_timeout_sec: int = 420  # whole build+run (dep install can be slow)
    # Repro container gets network so ARBITRARY open-source projects can install their
    # own dependencies (pip/npm). It stays ephemeral + resource-capped + cap-drop +
    # no host mount + used-and-thrown-away. Set false for strict no-egress (then only
    # projects whose deps are prebaked in the image are reproducible).
    sandbox_allow_network: bool = True

    # --- provisioner (deep mode: stand the target app up once, reuse for all PoCs) ---
    enable_provisioner: bool = True
    provisioner_max_steps: int = 16       # LLM-driven setup step cap (anti-loop)
    provisioner_timeout_sec: int = 900    # whole provisioning wall-clock budget
    provisioner_cmd_timeout_sec: int = 240  # single setup command timeout
    # one-time step EXTENSION when a build/preheat is clearly progressing (recent productive
    # actions) and steps are about to run out — mirrors the Validator's extension, so a nearly-
    # finished environment build isn't cut off right before it comes up.
    provisioner_step_extension: float = 1.5
    provisioner_step_hard_cap: int = 72   # absolute step ceiling after extension
    # When on, deep mode runs an extra LLM round to seed/migrate the DB EVEN IF the app
    # is already up — so DB-dependent vulns (SQLi etc.) can be dynamically reproduced.
    # Costs extra tokens per deep run; only fires when a DB-backed vuln candidate exists.
    provisioner_llm_enrich: bool = False

    # --- professional scanners (LLM-callable tools; graceful degradation if missing) ---
    enable_semgrep: bool = True           # semgrep_scan  (pattern SAST, breadth)
    enable_codeql: bool = False           # codeql_scan   (semantic dataflow, heavy; deep only)
    # Call-graph precision ladder: use CodeQL to refine call edges (reachability + call_path
    # + taint dataflow) for no-build languages (python/javascript/typescript; ruby left to
    # Joern). Degrades to Joern/Tree-sitter on any failure. CodeQL is memory-heavy (~1.4GB)
    # and can OOM on constrained machines → set false to disable.
    enable_codeql_callgraph: bool = True
    codeql_ram_mb: int = 1400             # RAM cap for codeql db-create / query
    codeql_timeout_sec: int = 300         # per codeql step timeout (build/query)
    # Joern: multi-language (incl. PHP/Go/Java, no build) call-graph fallback below CodeQL.
    # Needs the joern-cli dir + a JDK 17+ (auto-detected under D:/Tools; override here).
    enable_joern_callgraph: bool = True
    joern_dir: str = ""                   # path to joern-cli (auto-detect if empty)
    joern_java_home: str = ""             # JDK 17+ for joern (auto-detect if empty)
    joern_timeout_sec: int = 420          # per joern step timeout (parse/query)
    enable_secret_scan: bool = True       # secret_scan   (gitleaks)
    enable_dependency_scan: bool = True   # dependency_scan (osv-scanner)
    scanner_timeout_sec: int = 180

    # --- RAG semantic code retrieval (app/rag/*) ---
    # Builds a per-project vector index (incremental by file hash); the Hunter/Validator
    # query it with natural language via search_code_semantic. Backend ladder:
    #   auto      → fastembed (real semantic, offline ONNX) if installed, else hashing
    #   fastembed → force the local ONNX semantic model (model cached on D:)
    #   cloud     → the provider's embedding model via LiteLLM (needs API key; costs egress)
    #   hashing   → deterministic offline lexical vectorizer (no semantics; always works)
    enable_rag: bool = True
    rag_embed_backend: str = "auto"
    rag_embed_model: str = "BAAI/bge-small-en-v1.5"
    rag_fastembed_cache: str = "D:/Tools/fastembed_cache"  # keep the model off C:
    rag_hashing_dim: int = 512
    # embedding batch size. ONNX attention peak ≈ batch × layers × seq² × 4B (bge-small:
    # batch×12×512²×4). A deep run already spends ~1.4GB on CodeQL + Joern + Docker, so keep
    # this small: 8 ≈ 100MB. If fastembed still can't get the memory it OOM-degrades to the
    # dependency-free `hashing` backend (audit never fails).
    rag_embed_batch: int = 8
    rag_top_k: int = 8
    rag_hybrid_alpha: float = 0.7         # weight of semantic vs lexical in hybrid rerank
    rag_max_chunk_lines: int = 120
    rag_chunk_overlap: int = 15

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
            "provisioner": self.model_mid,   # env setup is semi-mechanical — mid tier
            "reporter": self.model_cheap,
        }
        return mapping.get(role, self.model_strong)


settings = Settings()
