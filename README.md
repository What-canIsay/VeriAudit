# VeriAudit — 基于多智能体的开源项目安全缺陷自动审计与验证系统

> **一句话定位**：VeriAudit 是一套以 **"验证驱动（Verification-first）"** 为核心的多智能体代码安全审计系统。它不满足于"用大模型扫出可疑点"，而是为每一个漏洞给出**可复现的 PoC、完整的证据链（文件位置 → 调用路径 → 污点流 → 验证结果）与置信度分级**，最终产出结构化审计报告。

VeriAudit 面向通用多语言开源项目，通过 **编排官 / 侦察员 / 漏洞猎手 / 污点追踪员 / 验证官 / 报告官** 六类具备工具调用能力的智能体协同工作，完成"发现 → 追踪 → 验证 → 利用 → 报告"的完整闭环。

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
| 多角色智能体协同 | 6 类智能体基于 LangGraph 状态机编排，支持并行、回环与动态子任务派生 |
| 工具调用 | 20+ 工具：代码检索、AST 查询、调用图/入口点分析、SAST 扫描、污点追踪、RAG 知识库、沙箱执行、PoC 运行等（见 [`docs/03-tools.md`](docs/03-tools.md)） |
| 自动化 PoC / 漏洞利用 | 验证官在隔离沙箱中自动构建目标环境、生成并运行利用代码，带自我纠错重试，产出可复现的漏洞利用代码 |
| 证据链 | 每个漏洞输出：入口点、source/sink、调用路径、污点流各跳、净化检查、可达性结论、静态与动态验证结果、产物（请求/响应、日志） |
| 结构化审计报告 | 漏洞列表、严重等级（CVSS 向量 + 分级）、证据链、修复建议；支持 Markdown / PDF / JSON / **SARIF**（可接入 CI）导出 |
| 多语言 | 通过"语言适配器"扩展，MVP 覆盖 Python / JavaScript·TypeScript / Java / Go / PHP |
| 云端强模型接入 | 通过 LiteLLM 以 API Key 接入云端强模型（默认推荐强代码推理模型）；**本地模型预留接口，暂不实现** |
| 优美前端 | 实时智能体执行时间线、证据链可视化图、报告工作台（见 [`docs/07-frontend-design.md`](docs/07-frontend-design.md)） |

---

## 文档索引

| 文档 | 内容 |
|---|---|
| [`docs/01-architecture.md`](docs/01-architecture.md) | 总体架构、分层、数据流、部署形态 |
| [`docs/02-agents-and-orchestration.md`](docs/02-agents-and-orchestration.md) | 六类智能体职责、LangGraph 编排、协作协议、状态机 |
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

当前为 **系统设计阶段**，本仓库仅包含设计文档，尚未落地代码。实施路线见 [`docs/09-tech-stack-and-roadmap.md`](docs/09-tech-stack-and-roadmap.md)。
