# 01 · 总体架构

## 1. 设计目标与约束

| 目标 | 约束 / 决策 |
|---|---|
| 通用多语言漏洞挖掘 | 通过"语言适配器"扩展；MVP 覆盖 Python / JS·TS / Java / Go / PHP |
| 输出可复现 PoC 与漏洞利用代码 | 隔离沙箱中自动构建目标环境、生成并运行利用代码，带自我纠错 |
| 每个漏洞输出完整证据链 | 证据链为一等数据对象（文件位置 / 调用路径 / 污点流 / 验证结果） |
| 结构化审计报告 | 漏洞列表 / 严重等级 / 证据链 / 修复建议；多格式导出（含 SARIF） |
| 云端强模型接入 | LiteLLM + API Key；**本地模型仅预留接口，暂不实现** |
| 优美前端 | 实时执行时间线、证据链图、报告工作台 |
| 能力不低于 DeepAudit | 双层验证 + 可达性优先 + 评估基准兜底 |

**非目标（本期不做）**：本地/私有化模型推理落地、IDE 插件、SaaS 多租户计费。

---

## 2. 分层架构

```
┌─────────────────────────────────────────────────────────────────────┐
│  展示层  Frontend (React + TS + Vite + Tailwind + shadcn/Radix)        │
│  · 项目管理  · 实时执行时间线  · 证据链可视化  · 报告工作台             │
└───────────────▲───────────────────────────────▲──────────────────────┘
                │ REST (控制)                    │ SSE (实时事件流)
┌───────────────┴───────────────────────────────┴──────────────────────┐
│  接入层  API Gateway (FastAPI)                                         │
│  · 认证鉴权  · 任务编排入口  · 事件流广播  · 报告导出                   │
└───────────────▲───────────────────────────────────────────────────────┘
                │ 任务派发 (Redis 队列)
┌───────────────┴───────────────────────────────────────────────────────┐
│  编排层  Orchestration Engine (LangGraph 状态机)                       │
│  · Agent 生命周期  · 状态持久化/断点续跑  · 事件发射  · 熔断/限流/重试   │
└──────┬──────────┬──────────┬──────────┬──────────┬──────────┬─────────┘
       │          │          │          │          │          │
   ┌───▼───┐ ┌────▼───┐ ┌────▼────┐ ┌───▼────┐ ┌───▼─────┐ ┌──▼─────┐
   │Planner│ │ Recon  │ │ Hunter  │ │ Tracer │ │Validator│ │Reporter│   智能体层
   │编排官 │ │侦察员  │ │漏洞猎手 │ │污点追踪│ │验证官   │ │报告官  │
   └───┬───┘ └────┬───┘ └────┬────┘ └───┬────┘ └───┬─────┘ └──┬─────┘
       └──────────┴──────────┴───┬──────┴──────────┴──────────┘
                                 │ 统一工具接口 (ToolCall)
┌────────────────────────────────▼──────────────────────────────────────┐
│  能力层  Capability Services                                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐ │
│  │ 代码索引  │ │ SAST 集成 │ │ 污点引擎 │ │ RAG 知识 │ │ 验证沙箱      │ │
│  │Code Index│ │ Scanners  │ │ Taint    │ │Knowledge │ │Verify Sandbox│ │
│  │ AST/调用图│ │Semgrep等  │ │source→sink│ │pgvector  │ │Docker 隔离   │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────────┘ │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ LLM 网关 (LiteLLM)  — 云端强模型 · 模型分级 · 缓存 · 用量统计       │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
┌───────────────────────────────────────────────────────────────────────┐
│  存储层  PostgreSQL(+pgvector) · Redis · 对象存储(报告/PoC产物/日志)     │
└───────────────────────────────────────────────────────────────────────┘
```

**分层职责**
- **智能体层**只负责"决策"——发出工具调用、消化结果、推进状态；不直接接触基础设施。
- **能力层**是无状态/可独立测试的确定性服务；智能体通过统一 `ToolCall` 接口调用。
- 这种解耦让**能力层可单独做单元测试与评估**（例如污点引擎的准确率），而不必跑整条智能体链路。

---

## 3. 端到端数据流（审计一次的生命周期）

```
①提交目标        ②侦察建索引        ③高召回发现         ④可达性追踪
Git URL / ZIP  →  Recon 构建:      →  Hunter 产候选:   →  Tracer 追踪:
                  · 技术栈/框架        · SAST 候选池       每个候选做
                  · 入口点/攻击面      · LLM 语义候选      source→sink
                  · 代码索引/调用图    · 知识库匹配        污点流+可达性
                                       （高召回、带自评）

⑤独立验证                       ⑥固化证据链           ⑦报告
Validator(全新上下文):        →  组装 EvidenceChain →  Reporter:
· 静态复核(逻辑类兜底)            · source/sink          · 漏洞列表
· 生成 PoC → 沙箱构建/运行        · 调用路径各跳          · CVSS 分级
· 自我纠错重试                    · 净化检查             · 证据链
· 判定置信度                      · 静态/动态验证结果     · 修复建议
                                                        · MD/PDF/JSON/SARIF
       ▲                                                       │
       └───────── 回环：证据不足则退回 Hunter/Tracer 补充 ──────┘
```

关键点：**发现阶段追求高召回（宁可多报）**，**验证阶段用全新上下文独立过滤**——两者职责分离是降误报的结构性保证（原理见 [`02-agents-and-orchestration.md`](02-agents-and-orchestration.md) §设计原则）。

---

## 4. 部署形态

### 4.1 组件拓扑（Docker Compose）

```
┌─ web (Nginx) ── 静态前端 + 反向代理
├─ api ────────── FastAPI (REST + SSE)
├─ worker ──────── 编排引擎 + 智能体执行 (Celery/arq 消费队列)
├─ sandbox-pool ── 一次性验证容器（每次 PoC 拉起、用后即焚，见 §4.2）
├─ postgres ────── 业务数据 + pgvector 向量
├─ redis ───────── 任务队列 + 缓存 + SSE 广播
└─ object-store ── 报告/PoC 产物/沙箱日志（MinIO 或本地卷）
```

`api` 与 `worker` 分离：API 保持轻量响应，重活（LLM 调用、扫描、沙箱）全在 worker，天然支持横向扩容。

### 4.2 沙箱的隔离边界（安全关键）

验证沙箱是系统内**风险最高**的部件——它同时运行"不可信的目标代码"和"LLM 生成的利用代码"。因此：

- 每次验证**拉起一次性容器**，与 worker/宿主网络隔离，**默认无出网**；
- 施加 `seccomp` + 只读根文件系统 + CPU/内存/超时限额 + 非 root 用户 + 能力最小化；
- 沙箱内**不注入任何密钥/凭据**；
- 用后即焚。

完整威胁模型见 [`08-security-threat-model.md`](08-security-threat-model.md)。

### 4.3 模型接入

- 统一经 **LiteLLM 网关**，云端模型以 **API Key** 配置；
- **模型分级**：推理密集型智能体（Hunter/Tracer/Validator）用强代码推理模型，轻量智能体（Recon/Reporter）可用更便宜的模型；
- 密钥在服务端加密存储，永不下发前端、永不进沙箱；
- **本地模型预留 `LocalModelProvider` 接口占位**，本期不实现（见 [`09`](09-tech-stack-and-roadmap.md)）。

---

## 5. 关键横切设计

| 横切关注点 | 设计 |
|---|---|
| 断点续跑 | 编排状态按节点 checkpoint 到 PostgreSQL；任务可暂停/恢复/重跑单节点 |
| 可观测性 | 每次工具调用、模型调用、token 用量、耗时全量结构化落库；前端时间线实时回放 |
| 稳定性 | LLM/工具调用统一走 重试 + 指数退避 + 熔断 + 降级模型 fallback |
| 成本控制 | 提示缓存复用只读前缀；预算护栏（单任务 token/时长上限）；SAST 先筛候选降低 LLM 调用量 |
| 幂等与去重 | Finding 以 `(vuln_type, sink_location, taint_signature)` 指纹去重 |
| 多语言扩展 | 语言适配器插件化（见下节） |

---

## 6. 多语言扩展机制：语言适配器

每种语言实现一个 `LanguageAdapter`，向能力层声明该语言的审计要素：

```yaml
LanguageAdapter (示例：python):
  tree_sitter_grammar: tree-sitter-python
  entrypoint_patterns:            # 攻击面识别
    - flask/django/fastapi 路由装饰器
    - CLI argv、消息队列消费者
  sast_tools: [semgrep(python), bandit]
  taint_catalog:
    sources: [request.args, request.form, os.environ, input(), ...]
    sinks:
      command_injection: [os.system, subprocess(shell=True), ...]
      sql_injection: [cursor.execute(拼接), ...]
      deserialization: [pickle.loads, yaml.load, ...]
      path_traversal: [open(用户输入), ...]
    sanitizers: [shlex.quote, 参数化查询, ...]
  sandbox_recipe:                 # 沙箱构建/运行配方
    base_image: python:3.11-slim
    install: [pip install -r requirements.txt]
    run: [uvicorn/flask run ...]
```

新增语言 = 新增一个适配器 + 一套污点目录，无需改动智能体与编排层。MVP 语言集：`python, javascript/typescript, java, go, php`。

---

## 7. 技术选型速览

> 详见 [`09-tech-stack-and-roadmap.md`](09-tech-stack-and-roadmap.md)。

| 层 | 选型 | 理由 |
|---|---|---|
| 后端 | Python 3.11 + FastAPI | 生态贴合 LLM/静态分析工具链 |
| 编排 | LangGraph | 天然表达"带回环的验证状态机" |
| 模型网关 | LiteLLM | 一层抽象多云模型，便于分级与替换 |
| 代码解析 | Tree-sitter (+ 可选 LSP) | 多语言、增量、AST 稳定 |
| 向量库 | PostgreSQL + pgvector | 复用主库，少一个组件（区别于 DeepAudit 的 ChromaDB） |
| 队列/缓存 | Redis + Celery/arq | 成熟、够用 |
| 沙箱 | Docker + seccomp | 强隔离、语言无关 |
| 前端 | React 18 + TS + Vite + Tailwind + shadcn/Radix + Zustand | 生态成熟、组件可达性好 |
| 图可视化 | Cytoscape.js / React Flow | 调用图与证据链渲染 |
