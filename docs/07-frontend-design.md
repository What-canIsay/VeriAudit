# 07 · 前端设计

目标：一个**优美、专业、信息密度高**的安全审计工作台。三个招牌界面——**实时执行时间线、证据链可视化、报告工作台**——是前端的差异化亮点。

## 1. 技术选型

| 关注点 | 选型 |
|---|---|
| 框架 | React 18 + TypeScript + Vite |
| 样式 | Tailwind CSS + shadcn/ui（基于 Radix，可达性好） |
| 状态 | Zustand（轻量）+ TanStack Query（服务端状态/缓存） |
| 实时 | 原生 `EventSource` 订阅 SSE |
| 图可视化 | React Flow（编排流程/证据链）+ Cytoscape.js（调用图，大图性能好） |
| 代码展示 | Shiki/CodeMirror 语法高亮 + 行级标注 |
| 图表 | 轻量图表库渲染统计（遵循统一色板与可达性规范） |

## 2. 视觉设计方向

- **主题**：深色为主（安全工具语境），支持浅色切换；主题令牌驱动，一处改全局。
- **色板语义化**：严重度用固定语义色（Critical=红 / High=橙 / Medium=黄 / Low=蓝 / Info=灰）；置信度用徽章区分（Dynamic=实心、Static=描边、Suspected=虚线）。**避免用颜色单独承载信息**（叠加图标/文案，满足色盲可达性）。
- **信息密度**：借鉴专业安全/可观测性面板（如 dashboard 风格），表格 + 侧栏详情 + 图，减少跳转。
- **克制的动效**：状态流转、时间线滚动用微动效，不喧宾夺主。

## 3. 页面地图

```
/login                        登录
/projects                     项目列表（卡片/表格；来源、语言、最近任务状态）
/projects/new                 新建项目（Git URL / 上传 ZIP）
/projects/:id                 项目详情（历史任务、代码画像、入口点概览）
/tasks/:id                    ★审计控制台（下述四个 Tab）
/tasks/:id/findings/:fid      漏洞详情（证据链可视化）
/reports/:id                  报告工作台
/settings/models              模型分级与密钥配置（管理员）
/settings/knowledge           知识库管理
```

## 4. 招牌界面

### 4.1 审计控制台 `/tasks/:id`（核心页）
四个 Tab：

- **① 概览 Overview**：进度环（各阶段）、漏洞计数矩阵（严重度 × 置信度）、预算/耗时/token 用量、当前活跃智能体。
- **② 执行时间线 Timeline**（★招牌）：
  - 消费 SSE，实时流式呈现"哪个智能体在做什么、调了什么工具、结果如何"；
  - 泳道式布局（每个智能体一条泳道，子任务缩进为子泳道）；
  - 每个事件卡片可展开：思考摘要、工具入参、结果摘要、token/耗时；
  - 支持暂停/恢复/取消任务；断线重连自动回补历史。
- **③ 漏洞 Findings**：可过滤表格（严重度/置信度/类型/入口点），点开进 4.2。
- **④ 代码图谱 Code Map**：调用图 + 入口点高亮（Cytoscape.js），可从入口点追到 sink。

### 4.2 证据链可视化 `/findings/:fid`（★招牌）
把 [`04`](04-verification-poc-evidence.md) 的证据链渲染成可交互视图：

```
┌ 顶部：标题 · CWE · 严重度(CVSS) · 置信度徽章 ─────────────────┐
├ 左：污点流图（React Flow）                                    │
│    entry_point ─▶ source ─▶ hop ─▶ hop ─▶ sink              │
│    · 节点点击 → 右侧联动高亮对应代码                          │
│    · 净化器缺失/被绕过的跳标红                                │
├ 右：代码面板（Shiki）                                        │
│    · 逐跳高亮 file:line，行级标注变量与处理                   │
├ 下：验证证据                                                 │
│    · 静态判定理由                                            │
│    · 动态：PoC 代码 + 成功的请求/响应 + 沙箱日志（可下载）     │
└ 底部操作：确认/标记误报/加备注（人工复核，回写 Finding 状态） │
```

支持"人工复核"闭环：审计员可确认、驳回或加注，回写到 Finding，纳入下次报告与评估回归集。

### 4.3 报告工作台 `/reports/:id`
- 在线阅读渲染后的报告；
- 一键导出 MD/PDF/JSON/**SARIF**；
- 版本对比（漏洞增减 diff）；
- 分享（受控只读链接，遵循权限）。

## 5. 组件清单（shadcn/ui 为基）

`AppShell/Sidebar/Topbar` · `ProjectCard` · `TaskProgressRing` · `SeverityBadge` · `ConfidenceBadge` · `TimelineLane/EventCard` · `TaintFlowGraph` · `CodeViewer` · `FindingsTable` · `CallGraphCanvas` · `ReportViewer` · `ModelConfigForm` · `KnowledgeManager`。

## 6. 可达性与性能

- 键盘可达、ARIA 标注、焦点管理（Radix 原生支持）；深浅主题对比度达标。
- 大图（调用图/大量事件）用虚拟化列表 + Canvas 渲染 + 分页/懒加载。
- 时间线事件本地缓冲后再渲染，避免高频 SSE 造成频繁重排。

> 实现阶段可借助内部 `ui-ux-pro-max` / `dataviz` 设计能力细化色板、组件与图表规范；本设计文档先锁定信息架构与交互骨架。
