# 05 · 数据模型与 API

## 1. 领域模型总览

```
User ──< Project ──< AuditTask ──┬──< Candidate ──< TracedCandidate
                                 ├──< Finding ──1─ EvidenceChain
                                 │                 └──< Artifact (PoC/请求响应/日志)
                                 ├──< AgentRun ──< ToolInvocation   (可观测/时间线)
                                 └──< Report (多格式版本)
Project ──1─ CodeIndex (调用图/AST/入口点/embedding 句柄)
```

- **Project**：一个被审计的代码库（Git URL 或上传的 ZIP 的某次快照/commit）。
- **AuditTask**：一次审计运行（含配置：语言集、深度档位、模型分级、预算）。
- **Candidate → TracedCandidate → Finding**：候选沿流水线逐级富化，最终成为确认漏洞。
- **AgentRun / ToolInvocation**：全量执行轨迹，驱动前端实时时间线与断点续跑。

---

## 2. 数据库 Schema（PostgreSQL + pgvector）

> 仅列关键表与字段；`id` 均为 UUID，省略 `created_at/updated_at`。

```sql
-- 用户与项目
user(id, email, password_hash, role, ...)          -- role: admin/auditor/viewer
project(id, owner_id, name, source_type, source_ref, commit_sha, languages jsonb, status)
    -- source_type: git_url | zip_upload

-- 审计任务与配置
audit_task(id, project_id, config jsonb, depth,        -- depth: fast/standard/deep
           status, round int, budget jsonb, started_at, finished_at)
    -- status: queued/running/paused/succeeded/failed/canceled

-- 代码索引（能力层产物的句柄/元数据；重物存对象存储或专用索引）
code_index(id, project_id, entrypoints jsonb, call_graph_ref, ast_stats jsonb)
code_chunk(id, project_id, path, span jsonb, lang, content text,
           embedding vector(1536))                  -- pgvector 语义检索
    -- ivfflat/hnsw 索引于 embedding

-- 漏洞发现流水线
candidate(id, task_id, vuln_type, location jsonb, self_confidence float,
          rationale text, origin)                   -- origin: sast/llm/kb/sca
traced_candidate(id, candidate_id, taint_path jsonb, reachability jsonb, reachable bool)
finding(id, task_id, vuln_type, title, confidence, severity jsonb,
        cvss_vector text, status)                   -- status: confirmed/suspected/rejected
evidence_chain(id, finding_id, entry_point jsonb, source jsonb, sink jsonb,
               taint_path jsonb, sanitizers jsonb, reachability jsonb,
               static_verdict jsonb, dynamic_verification jsonb)
artifact(id, finding_id, kind, storage_ref, meta jsonb)
    -- kind: poc_code | http_exchange | sandbox_log | canary_hit | screenshot

-- 执行轨迹（可观测性 / 时间线 / 断点续跑）
agent_run(id, task_id, agent, node, parent_run_id, status,
          input_slice jsonb, output jsonb, tokens jsonb, started_at, finished_at)
tool_invocation(id, agent_run_id, tool, args jsonb, result_summary jsonb,
                ok bool, cost_hint jsonb, ts)
checkpoint(id, task_id, node, state_blob_ref, ts)   -- LangGraph 状态快照

-- 报告
report(id, task_id, format, storage_ref, summary jsonb, version)
    -- format: markdown | pdf | json | sarif

-- 系统配置
model_config(id, owner_id, provider, model, api_key_enc, role_binding jsonb)
    -- role_binding: {hunter: strong, reporter: cheap, ...}；api_key 加密存储
knowledge_doc(id, vuln_type, framework, lang, content, embedding vector(1536))
```

**说明**
- `api_key_enc` 用应用级加密（KMS/对称密钥）存储，**永不下发前端、永不进沙箱**（见 [`08`](08-security-threat-model.md)）。
- 向量列（`code_chunk.embedding` / `knowledge_doc.embedding`）用 pgvector，复用主库，无需独立 ChromaDB。
- Finding 去重指纹：`hash(vuln_type + normalize(sink.location) + taint_signature)`。

---

## 3. 后端 API（FastAPI）

### 3.1 REST（控制面）

| Method & Path | 说明 |
|---|---|
| `POST /api/v1/auth/login` | 登录，签发 JWT |
| `POST /api/v1/projects` | 创建项目（Git URL 或上传 ZIP） |
| `GET /api/v1/projects` / `GET /api/v1/projects/{id}` | 项目列表 / 详情 |
| `POST /api/v1/projects/{id}/tasks` | 发起审计任务（body: 深度档位、语言、模型分级、预算） |
| `GET /api/v1/tasks/{id}` | 任务状态与进度概览 |
| `POST /api/v1/tasks/{id}/pause` / `/resume` / `/cancel` | 任务生命周期控制（断点续跑） |
| `GET /api/v1/tasks/{id}/timeline` | 执行轨迹（agent_run + tool_invocation 分页） |
| `GET /api/v1/tasks/{id}/findings` | 漏洞列表（可按 confidence/severity/type 过滤） |
| `GET /api/v1/findings/{id}` | 单漏洞详情（含完整证据链与产物引用） |
| `GET /api/v1/findings/{id}/artifacts/{aid}` | 下载 PoC / 请求响应 / 日志 |
| `POST /api/v1/tasks/{id}/report?format=sarif` | 生成/获取报告（md/pdf/json/sarif） |
| `GET /api/v1/config/models` / `PUT ...` | 模型分级与密钥配置（管理员） |
| `POST /api/v1/config/models/test` | 连通性测试（**须防 SSRF，见 08**） |

**约定**：所有列表分页（`?page&size`）；所有写操作校验角色权限（admin/auditor/viewer）。

### 3.2 SSE（实时事件流）

前端订阅一次任务的实时事件，驱动时间线与进度：

```
GET /api/v1/tasks/{id}/events   (text/event-stream)

event: task.status          data: {status, round, budget_left}
event: agent.started        data: {agent, node, run_id}
event: agent.thinking       data: {run_id, text}          # think 工具/思考摘要
event: tool.invoked         data: {run_id, tool, args_brief}
event: tool.result          data: {run_id, tool, ok, summary}
event: candidate.recorded   data: {vuln_type, location, self_confidence}
event: finding.confirmed    data: {finding_id, vuln_type, confidence, severity}
event: sandbox.poc_attempt  data: {finding_id, attempt, reproduced}
event: task.finished        data: {counts:{confirmed,suspected,rejected}}
```

事件同时落库（`agent_run`/`tool_invocation`），断线重连后可用 `GET /timeline` 回补历史（先拉历史去重、再续实时流）。

---

## 4. 关键状态机（任务）

```
queued → running ⇄ paused
           │
           ├─▶ succeeded
           ├─▶ failed
           └─▶ canceled
```

- `paused`：写 checkpoint，释放 worker；`resume` 从最近节点恢复。
- `failed`：保留已产出的 Finding 与轨迹，支持从失败节点重跑。

---

## 5. 与前端 / 报告的数据契约

- 前端时间线消费 SSE + `GET /timeline`；证据链视图消费 `GET /findings/{id}`。
- 报告导出复用同一批 Finding/EvidenceChain 数据，仅渲染格式不同（见 [`06`](06-report-design.md)）。
- **SARIF** 导出使 Finding 可直接接入 GitHub Code Scanning / CI 门禁。
