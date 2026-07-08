# VeriAudit — 基于多智能体的开源项目安全缺陷自动审计与验证系统

> **一句话定位**：VeriAudit 是一套以 **"验证驱动（Verification-first）"** 为核心的多智能体代码安全审计系统。它不满足于"用大模型扫出可疑点"，而是为每一个漏洞给出**可复现的 PoC、完整的证据链（文件位置 → 调用路径 → 污点流 → 验证结果）与置信度分级**，最终产出结构化审计报告。

VeriAudit 面向通用多语言开源项目，通过 **规模评估 → 编排官 / 侦察员 / 漏洞猎手 / 污点追踪员 / 环境构建官 / 验证官 / 报告官** 七类具备工具调用能力的智能体（外加一个前置的"规模评估"环节）协同工作，完成"评估 → 规划 → 侦察 → 发现 → 追踪 → 搭建 → 验证(实弹复现) → 报告"的完整闭环。

---

## 为什么做 VeriAudit（设计出发点）

LLM 做代码审计的真正瓶颈**不是"能不能发现漏洞"，而是"误报"**——大模型很容易报出一堆看似成立、实则不可达/已被过滤/根本触发不到的可疑点。传统 SAST 误报同样严重且看不懂业务逻辑。

VeriAudit 的名字（**Veri**fication + **Audit**）即定位：**把"验证"和"降误报"做成第一竞争力**。三条主线贯穿全系统：

1. **可达性优先**：对每个候选漏洞独立追踪 `不可信输入(source) → 危险汇聚点(sink)` 的污点路径，先回答"这个 sink 到底可不可达"——这是降误报最有效的一刀。
2. **双层验证**：静态数据流验证（推理级）+ 动态沙箱 PoC 验证（复现级），并给出**诚实的置信度分级**，而非二元的"验证/未验证"。
3. **证据链一等公民**：证据链不是报告里的一段文字，而是贯穿全系统的结构化数据对象，可视化、可导出、可追溯。

---

## 核心能力

| 能力 | 说明 |
|---|---|
| 多角色智能体协同 | 7 类智能体 + 前置"规模评估"，由单进程 asyncio 状态机（LangGraph 式）编排；漏洞猎手、环境构建官、验证官为 agentic（模型自主编排工具） |
| 规模自适应预算 | 审计前评估项目规模/复杂度，据此自动推算各阶段步数/超时/名额等所有上限，小项目省、大项目够用（`app/profiler.py`） |
| 工具调用 | 20+ 工具：代码检索、入口点/攻击面分析、Semgrep/CodeQL/Gitleaks/OSV 扫描、污点追踪、知识库、沙箱执行等（见 [`docs/03-tools.md`](docs/03-tools.md)） |
| 环境构建官 + 核验预热 | deep 档由模型自主把目标应用在沙箱里搭起来，并按项目自适应地预热（建测试账号、按角色登录、seed 数据），供后续复现复用 |
| agentic 深度核验 + 实弹复现 | 验证官读全跨文件上下文，并在常驻应用上用 **sqlmap / nuclei / strace / 白盒 SQL 日志 / 带鉴权 HTTP 探针** 实弹触发漏洞，产出精确 PoC 与动态复现证据 |
| 证据链 | 每个漏洞输出：入口点、source/sink、调用路径、污点流各跳、净化检查、可达性结论、静态与动态验证结果、产物（请求/响应、日志） |
| 结构化审计报告 | 漏洞列表、严重等级（CVSS 向量 + 分级）、证据链、修复建议；支持 Markdown / JSON / **SARIF**（可接入 CI）导出 |
| 多语言 | 通过"语言适配器"扩展，覆盖 Python / JavaScript·TypeScript / Java / Go / PHP |
| 云端强模型接入 | 通过 LiteLLM 以 API Key 接入云端强模型；无 Key 时自动进入 Mock 模式全程离线可跑；**本地模型预留接口，暂不实现** |
| 优美前端 | 实时智能体执行时间线（含模型思考过程）、证据链可视化、报告工作台、历史任务回看（见 [`docs/07-frontend-design.md`](docs/07-frontend-design.md)） |

---

## 文档索引

| 文档 | 内容 |
|---|---|
| [`docs/01-architecture.md`](docs/01-architecture.md) | 总体架构、分层、数据流、部署形态 |
| [`docs/02-agents-and-orchestration.md`](docs/02-agents-and-orchestration.md) | 智能体职责、编排、协作协议、状态机 |
| [`docs/03-tools.md`](docs/03-tools.md) | 工具目录与接口规范（每个智能体调用哪些工具） |
| [`docs/04-verification-poc-evidence.md`](docs/04-verification-poc-evidence.md) | 双层验证流水线、沙箱、PoC 自动生成、证据链数据模型 |
| [`docs/05-data-model-and-api.md`](docs/05-data-model-and-api.md) | 数据模型、数据库 Schema、后端 REST + SSE API |
| [`docs/06-report-design.md`](docs/06-report-design.md) | 审计报告结构、严重度评分、导出格式（含 SARIF） |
| [`docs/07-frontend-design.md`](docs/07-frontend-design.md) | 前端页面、组件、可视化与视觉设计规范 |
| [`docs/08-security-threat-model.md`](docs/08-security-threat-model.md) | 审计器自身的安全威胁模型（沙箱、提示注入、密钥、SSRF 等） |
| [`docs/09-tech-stack-and-roadmap.md`](docs/09-tech-stack-and-roadmap.md) | 技术选型、评估基准、实施路线图与里程碑 |

---

## 与 DeepAudit 的关系与差异（合规声明）

VeriAudit 在**产品形态与总体范式**上参考了开源项目 [DeepAudit](https://github.com/lintsinghua/DeepAudit)（多智能体 + RAG + 沙箱验证，这是该领域的通用范式），但**不复用其任何源代码、模块命名或提示词**，并在架构上做了明确的自主设计与差异化：

| 维度 | DeepAudit | VeriAudit 的差异化设计 |
|---|---|---|
| 智能体分工 | Orchestrator / Recon / Analysis / Verification 四角色 | **将"污点可达性追踪"独立成 Tracer 角色**，并强化"发现（高召回）"与"验证（独立复核）"的职责分离 |
| 验证 | 侧重沙箱 PoC 验证 | **双层验证 + 置信度分级**：静态数据流验证兜底逻辑类漏洞，动态 PoC 作为铁证级结论 |
| 证据链 | 报告字段 | **证据链为贯穿全系统的一等数据对象**，含污点流各跳与净化检查，可视化/可导出/可追溯 |
| 误报控制 | — | **"高召回发现 + 独立验证过滤"** 的显式流水线（详见 02 文档设计原则） |
| 向量存储 | ChromaDB（独立组件） | **pgvector**（复用 PostgreSQL，少维护一个组件） |
| 自身安全 | 曾被报出 SSRF / 默认弱口令超管等问题 | **将"审计器自身安全"作为独立设计文档**（08），从威胁建模层面规避同类问题 |
| 质量保障 | — | **评估基准先行**：内置 OWASP Benchmark / SARD 等评测与回归集（09 文档） |

> DeepAudit 源码位于本机 `D:\my_allkinds_document\aaDa3_xia\DeepAudit`，仅作为**范式参照与差异化依据**，VeriAudit 的所有设计均为独立产出。

---

## 状态

**已落地并可运行**：后端（FastAPI + SQLite + LiteLLM，单进程 asyncio 编排 + SSE）、前端（React + Vite + Tailwind）、Docker 沙箱与专业工具链均已实现，支持 Mock 与云端两种模式。**部署与运行见 [`LAUNCH.md`](LAUNCH.md)**（含完整环境变量表、依赖与故障排查）。

### 实现现状 vs 设计文档（对齐说明）

`docs/01–09` 为**原始设计文档**，落地时对部分设计做了工程化取舍，并新增了几个角色/机制。以下是与设计文档的主要差异，以实现为准：

| 项 | 设计文档 | 实际实现 |
|---|---|---|
| 编排运行时 | LangGraph | 单进程 **asyncio 状态机**（LangGraph 式，无外部运行时依赖） |
| 存储 / 知识库 | PostgreSQL + pgvector / ChromaDB RAG | 默认 **SQLite**；知识库为内置规则库（`knowledge.py`），非向量 RAG |
| 智能体 | 编排官/侦察员/漏洞猎手/污点追踪员/验证官/报告官（6） | **新增 环境构建官(Provisioner)**（deep 档搭建 + 核验预热）；**新增前置"规模评估(Profiler)"** 计算自适应预算 |
| 验证官 | 单轮静态判定 + 沙箱 PoC | 升级为 **agentic 深度核验**：自主读全上下文 + 用 sqlmap/nuclei/strace/白盒 SQL 日志/带鉴权探针**实弹复现**；含每候选自适应步数、接近成功续步、回落止损 |
| 报告导出 | Markdown / PDF / JSON / SARIF | Markdown / JSON / SARIF（PDF 暂未实现） |

> 若需要把某一篇设计文档（如 02/03/04）与当前实现逐条对齐重写，可单独提出。
