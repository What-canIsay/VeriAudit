# 06 · 审计报告设计

报告是交付物的门面。VeriAudit 报告的差异化在于：**每个漏洞都带四段式证据链与置信度**，并支持机器可读的 **SARIF** 以接入 CI。

## 1. 报告结构

```
审计报告
├─ 1. 概要 Executive Summary
│   · 项目信息（名称/来源/commit/语言/规模）
│   · 审计配置（深度档位/模型/耗时/覆盖入口点数）
│   · 结果总览：按严重度 & 置信度的漏洞计数矩阵
│   · 风险评级与一句话结论
├─ 2. 漏洞列表 Findings（按 严重度 → 置信度 排序）
│   每条 Finding：
│     · 标题 + CWE + 严重度(CVSS向量/分/级) + 置信度徽章
│     · 位置速览：entry_point / source / sink
│     · 证据链（四段式，见 §3）
│     · PoC / 复现步骤 + 产物（请求响应/日志）
│     · 修复建议（原理 + 具体改法 + 参考）
├─ 3. 依赖与密钥问题（SCA / Secret，来自 dependency_audit / secret_scan）
├─ 4. 已排除项 Appendix（REJECTED：为何判定不成立）—— 体现审计完整性
└─ 5. 方法与局限 Methodology（覆盖范围、置信度含义、未覆盖面声明）
```

> §4「已排除项」是 VeriAudit 有意保留的部分：把"看起来像但被验证排除"的候选也交代清楚，让报告可信、可复核，而不是只报"命中"。

---

## 2. 严重度评分（CVSS v3.1）

由 `cvss_score` 工具依据证据链要素推导，避免主观拍脑袋：

| CVSS 维度 | 取值依据（来自证据链） |
|---|---|
| Attack Vector (AV) | entry_point 类型：网络路由→N，本地 CLI→L |
| Attack Complexity (AC) | reachability.preconditions 是否复杂 |
| Privileges Required (PR) | 到达 sink 是否需认证/授权 |
| User Interaction (UI) | 是否需诱导用户 |
| Scope (S) | 是否可影响越权范围/其他组件 |
| C/I/A | 漏洞类型的固有影响（如命令注入→C:H/I:H/A:H） |

输出：`CVSS:3.1/AV:N/AC:L/...` 向量 + 分值 + 分级（Critical/High/Medium/Low/Info）。分级与置信度**正交呈现**——一个 Critical 但 SUSPECTED 的漏洞会明确提示"高危但需人工确认"。

---

## 3. 证据链在报告中的呈现（四段式）

每个 Finding 的证据链渲染为四个小节，与 [`04`](04-verification-poc-evidence.md) 的数据模型一一对应：

```
① 在哪    entry_point / source / sink 的 文件:行 + 代码片段
② 怎么到的 taint_path 逐跳表格：文件:行 | 变量 | 该跳处理 | 说明
③ 为什么成立 可达性结论 + 净化器检查（哪些缺失/被绕过）
④ 凭什么信 静态判定理由 + 动态复现（PoC 代码 + 成功的请求/响应 + 日志摘录）
```

Markdown/PDF 中以代码块 + 表格呈现；前端中以交互式图呈现（见 [`07`](07-frontend-design.md)）。

---

## 4. 修复建议

每类漏洞的修复建议由 `kb_search` 的修复范式知识 + 具体上下文生成，包含：
- **根因**：为什么这里会成立（结合本项目的 sink 与缺失的净化）；
- **改法**：针对性代码级建议（如"改用参数化查询"并给出该框架的写法）；
- **加固**：纵深防御建议（输入校验/最小权限/框架安全配置）；
- **参考**：CWE、OWASP、框架安全文档链接。

---

## 5. 导出格式

| 格式 | 用途 |
|---|---|
| **Markdown** | 人读、可提交到仓库/Wiki |
| **PDF** | 正式交付、归档 |
| **JSON** | 二次处理、集成 |
| **SARIF** | 接入 GitHub Code Scanning / CI 门禁——每个 Finding 映射为 SARIF `result`，位置映射 sink，`level` 映射严重度，`codeFlows` 映射污点路径（证据链天然适配 SARIF 的 codeFlow 结构） |

> SARIF 支持是 VeriAudit 面向工程化落地的关键：证据链的 `taint_path` 恰好可无损映射为 SARIF 的 `codeFlows/threadFlows`，让污点路径在 GitHub 安全面板中可视化。

---

## 6. 报告版本化

同一任务可多次生成报告（如补充人工复核后重跑验证）。`report` 表按 `version` 存多版本，前端可对比不同版本的漏洞增减。
