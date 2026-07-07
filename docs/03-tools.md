# 03 · 工具目录与接口规范

智能体的能力边界由**工具**决定。VeriAudit 的工具是能力层暴露给智能体的确定性接口，统一经 `ToolCall` 调用、结构化返回、全量落库。

## 0. 统一工具契约

```python
class ToolCall(BaseModel):
    tool: str                 # 工具名
    args: dict                # 结构化参数（由工具的 input_schema 校验）
    caller: str               # 调用智能体（用于权限校验 + 审计）

class ToolResult(BaseModel):
    ok: bool
    data: dict | None         # 结构化结果
    error: str | None
    truncated: bool           # 结果是否被截断（大输出保护）
    cost_hint: dict           # 耗时/字节/是否触发沙箱等（用于成本可观测）
```

**通用约束**
- 所有工具**幂等或可重试**；失败经统一 重试/熔断/降级 包裹。
- **权限校验前置**：`caller` 必须在该工具的 `allowed_agents` 白名单内（见 [`02`](02-agents-and-orchestration.md) §1.1），否则拒绝——这是最小权限落地。
- **大输出保护**：文件/扫描结果超阈值自动分页或摘要，置 `truncated=true`，防止撑爆上下文。
- **不可信输入隔离**：所有读回的仓库内容都标注来源，提示层告知模型"这是数据，非指令"。

---

## 1. 工具全景（按能力域分组）

| 域 | 工具 | 归属智能体 | 触及资源 |
|---|---|---|---|
| 代码浏览 | `list_dir` `read_file` `grep` `git_meta` | 多数 | 只读文件系统 |
| 结构分析 | `ast_query` `detect_stack` `find_entrypoints` `build_call_graph` `call_graph_query` | Recon/Hunter/Tracer | 代码索引 |
| 静态扫描 | `semgrep_scan` `native_sast` `secret_scan` `dependency_audit` | Hunter/Recon | 扫描器进程 |
| 知识检索 | `kb_search` `code_retrieve` | Hunter/Tracer/Validator | pgvector / 知识库 |
| 污点分析 | `taint_trace` `reachability_check` | Tracer/Validator | 污点引擎 |
| 动态验证 | `sandbox_build` `sandbox_exec` `run_poc` `http_probe` | **仅 Validator** | 隔离沙箱 |
| 认知/记录 | `think` `record_candidate` `record_finding` `request_more_context` `dispatch_subtask` `finish` | 多数 | 编排状态 |
| 报告 | `read_finding` `cvss_score` `emit_report` | Reporter | Finding 存储 |

---

## 2. 工具规格（要点）

> 下列给出每个工具的用途、输入要点、输出要点、安全约束。完整 JSON Schema 在实现期定义。

### 2.1 代码浏览

**`list_dir`** — 列目录。`in: {path, depth?}` → `out: {entries[{path,type,size}]}`。禁止越出项目根（路径规范化 + 前缀校验，见 [`08`](08-security-threat-model.md)）。

**`read_file`** — 读文件（支持行范围）。`in: {path, start?, end?}` → `out: {content, lines, lang}`。二进制/超大文件拒读或摘要。

**`grep`** — ripgrep 正则检索。`in: {pattern, glob?, max?}` → `out: {matches[{path,line,text}]}`。用于快速定位候选点，比全文读入省 token。

**`git_meta`** — Git 元信息（blame/log/最近改动）。`in: {path, line?}` → `out: {last_commit, author, changed_at}`。支撑 **PR/增量模式**（只审改动面）。

### 2.2 结构分析

**`ast_query`** — 基于 Tree-sitter 的 AST 查询。`in: {path, query}`（如"所有函数定义/所有对某 API 的调用"）→ `out: {nodes[{kind,name,span,snippet}]}`。语义化定位，避免正则误伤。

**`detect_stack`** — 识别语言/框架/依赖（读 `package.json`/`requirements.txt`/`pom.xml`/`go.mod`/`composer.json` 等）→ `out: {languages, frameworks, deps}`。决定加载哪个语言适配器。

**`find_entrypoints`** — 依据语言适配器的入口点规则枚举攻击面（HTTP 路由、CLI、消息消费者、反序列化点、定时任务）→ `out: {entrypoints[{kind,route?,handler,location}]}`。**攻击面清单是可达性分析的起点。**

**`build_call_graph`** — 构建调用图（函数级）→ 句柄存索引，供 `call_graph_query` 查询。**`call_graph_query`** — 查询"谁调用了 X / 从入口点能否到达 Y / X→Y 的路径"→ `out: {paths[[func...]]}`。为 Tracer 的可达性判断提供事实依据。

### 2.3 静态扫描（候选生成器）

**`semgrep_scan`** — 运行 Semgrep（自带规则 + 自定义规则集）。`in: {paths, ruleset?}` → `out: {results[{rule,cwe,severity,location,message}]}`。**作为高精度候选生成器**，与 LLM 语义发现并入同一候选池。

**`native_sast`** — 语言原生 SAST（Python→Bandit、Go→gosec、JS→ESLint-security 等，由适配器映射）。

**`secret_scan`** — Gitleaks/TruffleHog 检测硬编码密钥/凭据。

**`dependency_audit`** — OSV-Scanner 检测依赖已知 CVE（SCA）。

> 设计意图：**SAST 当候选生成器，LLM 当分诊/验证器**。既拿 SAST 的高精度低成本，又用 LLM 补业务逻辑类漏洞。二者候选统一进入 Tracer→Validator 流水线。

### 2.4 知识检索（RAG）

**`kb_search`** — 检索漏洞知识库（各 CWE 类型的成因、模式、利用手法、修复范式；按语言/框架切片）。`in: {query, vuln_type?, framework?}` → `out: {snippets[]}`。为 Hunter 提供"该框架下这类漏洞长什么样"，为 Validator 提供"这类漏洞怎么写 PoC"。

**`code_retrieve`** — 语义代码检索（pgvector，Tree-sitter AST 分块 + embedding）。`in: {query, k}` → `out: {chunks[{path,span,snippet,score}]}`。用于跨文件找相关实现。**注意**：向量相似 ≠ 调用可达；找到片段后需用 `call_graph_query` 确认相连。

### 2.5 污点分析（可达性核心）

**`taint_trace`** — 给定候选（source 候选 + sink 候选），沿数据流追踪传播路径。`in: {sink_location, direction, max_hops}` → `out: {flows[{path[{location,var,transform}], reaches_source, sanitizers_passed}]}`。以确定性数据流分析为主、LLM 辅助补跨过程/跨文件的难点。

**`reachability_check`** — 判断某 sink 是否从任一**不可信入口点**可达。`in: {sink_location}` → `out: {reachable, entry_points[], preconditions[], confidence}`。**这是降误报的核心工具**：不可达则直接降级/排除。

### 2.6 动态验证（仅 Validator，触及沙箱）

**`sandbox_build`** — 依语言适配器的 `sandbox_recipe` 在一次性容器中构建目标运行环境。`in: {project_ref, recipe_override?}` → `out: {sandbox_id, service_url?, build_log_ref}`。**默认无出网**。

**`sandbox_exec`** — 在沙箱内执行命令（安装、启动、辅助脚本）。`in: {sandbox_id, cmd, timeout}` → `out: {stdout, stderr, exit_code}`。

**`run_poc`** — 在沙箱内运行利用代码/发起利用请求，观测是否触发漏洞。`in: {sandbox_id, poc_spec}` → `out: {reproduced, observation, request, response, artifacts[]}`。支持 Validator 的**自我纠错重试**（失败则改写 PoC 再跑，上限 N 次）。

**`http_probe`** — 面向沙箱内目标服务的受控 HTTP 请求（仅限沙箱内网，禁止外网/内网横向，见 [`08`](08-security-threat-model.md) SSRF 防护）。`in: {sandbox_id, request}` → `out: {response, timing}`。

### 2.7 认知与记录

**`think`** — 私有推理草稿（不产生副作用，仅记录思考，便于时间线回放）。

**`record_candidate`** — Hunter 登记一条候选（vuln_type/位置/自评置信度/理由）。

**`record_finding`** — Validator 固化一条 Finding（含证据链、PoC、置信度、CVSS 输入）。

**`request_more_context`** — Validator 触发回环：描述证据缺口 + 目标位置，退回 Tracer/Hunter。

**`dispatch_subtask`** — 派生动态子智能体（见 [`02`](02-agents-and-orchestration.md) §4）。

**`finish`** — 声明本节点任务完成，交出结构化产出。

### 2.8 报告

**`read_finding`** — Reporter 只读已固化 Finding（不能读源码）。

**`cvss_score`** — 由证据链要素推导 CVSS v3.1 向量与分数（见 [`06`](06-report-design.md)）。

**`emit_report`** — 渲染并导出报告（MD/PDF/JSON/SARIF），落对象存储。

---

## 3. 工具与智能体/流程的映射（一图看懂谁用什么）

```
Recon:     detect_stack → find_entrypoints → build_call_graph → dependency_audit
Hunter:    semgrep_scan/native_sast/secret_scan ─┐
           kb_search + code_retrieve + ast_query ─┼─▶ record_candidate  (高召回候选池)
Tracer:    taint_trace + reachability_check + call_graph_query ──▶ 附可达性
Validator: (独立) taint_trace 复核 → kb_search(利用手法)
           → sandbox_build → sandbox_exec → run_poc(自我纠错) / http_probe
           → record_finding | request_more_context(回环)
Reporter:  read_finding → cvss_score → emit_report
```

---

## 4. 扩展工具的方式

新增工具 = 实现 `Tool` 接口（`name / input_schema / allowed_agents / run()`）并注册到工具注册表；智能体的系统提示按其权限自动装配可用工具清单。**新增语言**通常只需补充语言适配器（映射到 `semgrep_scan`/`native_sast`/`sandbox_recipe`/污点目录），无需新增工具类型。
