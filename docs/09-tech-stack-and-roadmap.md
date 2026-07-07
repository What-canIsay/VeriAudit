# 09 · 技术选型、评估基准与实施路线图

## 1. 技术选型全表

| 层 | 选型 | 理由 / 备注 |
|---|---|---|
| 语言/后端 | Python 3.11 + FastAPI | 贴合 LLM/静态分析工具链；异步 IO 适配 SSE |
| 编排 | LangGraph | 表达"带回环的验证状态机"，支持 checkpoint/断点续跑 |
| 任务/并发 | Redis + Celery 或 arq | 队列、缓存、SSE 广播 |
| 模型网关 | LiteLLM | 一层抽象多云模型，支持模型分级与整体替换 |
| 代码解析 | Tree-sitter（可选 LSP 增强） | 多语言、增量、AST 稳定 |
| 污点/调用图 | 自研污点引擎（Tree-sitter AST + 数据流）+ 语言适配器 | 确定性为主、LLM 辅助补跨过程难点 |
| SAST 集成 | Semgrep（多语言）+ 原生 SAST（Bandit/gosec/…）| 候选生成器 |
| SCA/密钥 | OSV-Scanner / Gitleaks / TruffleHog | 依赖 CVE 与密钥检测 |
| 向量库 | PostgreSQL + pgvector | 复用主库（区别于 DeepAudit 的独立 ChromaDB） |
| 沙箱 | Docker + seccomp（一次性容器） | 强隔离、语言无关 |
| 对象存储 | MinIO / 本地卷 | 报告、PoC 产物、沙箱日志 |
| 前端 | React 18 + TS + Vite + Tailwind + shadcn/Radix + Zustand + TanStack Query | 见 [`07`](07-frontend-design.md) |
| 图可视化 | React Flow + Cytoscape.js | 证据链/调用图 |
| 部署 | Docker Compose（api / worker / sandbox-pool / postgres / redis / web / object-store） | 见 [`01`](01-architecture.md) §4 |

---

## 2. 模型接入与分级

### 2.1 云端接入（本期实现）
统一经 LiteLLM，以 **API Key** 配置。**模型分级**按智能体绑定：

```yaml
model_bindings:
  hunter:    { provider: <云厂商>, model: claude-opus-4-8, thinking: adaptive, effort: high }
  tracer:    { provider: <云厂商>, model: claude-opus-4-8, thinking: adaptive, effort: high }
  validator: { provider: <云厂商>, model: claude-opus-4-8, thinking: adaptive, effort: high }
  planner:   { provider: <云厂商>, model: <中档模型> }
  recon:     { provider: <云厂商>, model: <轻量模型> }
  reporter:  { provider: <云厂商>, model: <轻量模型> }
  embedding: { provider: <云厂商>, model: <text-embedding 模型> }
```

- **默认推荐**：发现/追踪/验证三大推理智能体用当前最强代码推理模型（默认 `claude-opus-4-8`，开启自适应思考、`effort=high`——代码找 bug 与验证是智能核心）；Recon/Reporter 用便宜模型控成本。
- 全部经配置声明，**可整体替换**为任意 LiteLLM 支持的云端模型；密钥加密存储（见 [`08`](08-security-threat-model.md)）。

### 2.2 本地模型（预留接口，本期不实现）
- 定义统一 `ModelProvider` 抽象；`CloudProvider`（LiteLLM）本期落地，`LocalProvider`（如 Ollama/vLLM）**留占位接口与配置项，不实现推理**；
- 数据模型 `model_config.provider` 已预留 `local` 取值；
- 后续接本地模型无需改动智能体/编排/工具层——仅新增一个 Provider 实现。

---

## 3. 评估基准（质量兜底，"不低于 DeepAudit"的量化保证）

**没有评估就没有可信度。** 在扩展功能前先建评估闭环：

| 用途 | 数据/方法 |
|---|---|
| 精确率/召回率基线 | OWASP Benchmark、SARD/Juliet Test Suite（带标注的真/假阳样本） |
| 真实漏洞回归 | CVEfixes、以及"复现 DeepAudit 公布 CVE 的目标项目"作为验收样本 |
| 内部回归集 | 每次人工复核确认/驳回的 Finding 回流为回归用例，防止改动引入退化 |
| 指标 | Precision / Recall / F1、误报率、PoC 复现率、单漏洞平均成本(token/时长) |

参考索引：社区维护的 `Awesome-LLMs-for-Vulnerability-Detection`（数据集/基准/同类研究）。

**验收目标（示例，可校准）**：在标注基准上 Precision ≥ 基线、Recall 不低于 DeepAudit 同类配置；可复现类漏洞 PoC 复现率达标；对 DeepAudit 已公布 CVE 的目标项目能复现命中。

---

## 4. 实施路线图（里程碑）

> 与 [`02`](02-agents-and-orchestration.md) §6 的裁剪档位对应，从"验证闭环"切入，逐步展开。

### M0 · 骨架与评估（先立地基）
- FastAPI + LangGraph + LiteLLM + PostgreSQL/pgvector + Redis 打通；
- 语言适配器框架（先 Python）；代码索引（Tree-sitter AST + 入口点 + 调用图）；
- **评估 harness + OWASP/SARD 基线**（先能量化，再谈优化）。

### M1 · 最小验证闭环（MVP，主打降误报）
- Hunter（SAST 候选池 + LLM 语义，高召回）→ Tracer（可达性闸门）→ Validator（第 1 层静态验证）→ Finding + 证据链；
- **PR/增量模式优先**（只审改动面，信噪比与成本最优）；
- 基础报告（MD/JSON）+ 基础前端（时间线 + 漏洞列表 + 证据链视图）；
- **对应 Fast 档位**。先把"发现→可达性→静态验证→证据链"跑通并在基准上达标。

### M2 · 动态验证与 PoC（核心竞争力）
- 验证沙箱（一次性容器 + seccomp + 无出网）；
- PoC 自动生成 + 自我纠错循环 + Oracle 判据（先覆盖注入/路径穿越/SSRF 等可复现类）；
- 置信度分级（CONFIRMED_DYNAMIC 落地）；产物固化与前端展示；
- **对应 Standard 档位**。

### M3 · 广度与工程化
- 多语言铺开（JS/TS、Java、Go、PHP 适配器）；
- 知识库扩充（框架/漏洞类型）；SARIF 导出 + CI 接入；
- 动态子任务、Deep 档位、断点续跑完善；
- 前端打磨（招牌三界面、深浅主题、可达性）。

### M4 · 生产化
- 安全加固全项落地（[`08`](08-security-threat-model.md) 清单）、可观测性、成本护栏、多用户 RBAC；
- 本地模型 Provider 落地（若届时需要）；
- 回归集持续运营，指标看板。

---

## 5. 风险与权衡（诚实记录）

| 风险 | 缓解 |
|---|---|
| 污点分析跨过程/跨语言难做全 | 确定性引擎兜底 + LLM 辅助 + 证据不足降级为 SUSPECTED，不硬报 |
| 沙箱自动构建目标环境成功率有限 | 构建失败则回落静态结论；提供 recipe 覆盖与人工补配置入口 |
| 强模型成本高 | 模型分级 + SAST 先筛 + 提示缓存 + 预算护栏 + 增量模式 |
| 逻辑类漏洞难验证 | 双层验证中静态层专门兜底，置信度如实标注 |
| 与 DeepAudit 同质化 | 以"验证前置 + 可达性独立 + 证据链一等对象 + 自身安全 + 评估先行"形成差异（见 [`README`](../README.md) 差异表） |

---

## 6. 总结

VeriAudit 以"**验证驱动**"为主轴：高召回发现 → 可达性闸门 → 独立双层验证 → 一等证据链 → 结构化报告，并以**评估基准**保证质量、以**自身威胁模型**保证工具本身可信。它在总体范式上参考 DeepAudit，但在"降误报、证据链、自身安全、可评估"四个方向上做出实质性的自主设计与增强。
