# LAUNCH · 部署与运行指南

VeriAudit 是一个多智能体代码安全审计与验证系统，采用**前后端分离**架构：

- **后端** `backend/` — Python + FastAPI（智能体编排、工具、双层验证、沙箱、报告）
- **前端** `frontend/` — React + TypeScript + Vite（实时控制台、证据链可视化、报告工作台）

系统设计为**单机零基础设施即可启动**：默认 SQLite、单进程编排；**未配置 API Key 时以 Mock 模型模式运行全流程**（离线即可演示，产出真实的证据链与静态验证）；配置 Key 后切换为云端强模型。

---

## 1. 环境要求

| 组件 | 版本 | 必需 | 说明 |
|---|---|---|---|
| Python | ≥ 3.9 | ✅ | 后端运行时 |
| Node.js | ≥ 18 | ✅ | 前端构建/开发（本项目在 Node 24 验证） |
| Docker | ≥ 20 | 可选 | **动态沙箱 PoC 验证**；缺失则自动降级为静态验证 |
| Semgrep | 任意 | 可选 | 增强 SAST 候选；缺失则自动跳过 |

> 未装 Docker/Semgrep 也能完整运行，只是不做动态复现 / 不用 Semgrep 候选。

---

## 2. 后端启动

```bash
cd backend

# 1) 创建虚拟环境
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

# 2) 安装依赖
pip install -r requirements.txt

# 3)（可选）配置环境变量：复制示例并填写
copy .env.example .env        # Windows
# cp .env.example .env        # macOS/Linux
#   - 留空 VERIAUDIT_LLM_API_KEY => Mock 模型模式（离线可跑）
#   - 填入 Key                   => 云端强模型模式

# 4) 启动 API（默认 http://localhost:8000）
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

验证：浏览器/curl 访问

- 健康检查：`http://localhost:8000/healthz`
- 运行时配置：`http://localhost:8000/api/v1/config`
- 交互式 API 文档：`http://localhost:8000/docs`

---

## 3. 前端启动

新开一个终端：

```bash
cd frontend
npm install
npm run dev           # 默认 http://localhost:5173
```

浏览器打开 **http://localhost:5173** 。前端开发服务器已配置代理，`/api` 与 `/healthz` 自动转发到后端 `:8000`（含 SSE 事件流），无需额外配置。

---

## 4. 快速体验（内置漏洞样本）

仓库自带一个**故意留有漏洞**的样本 `samples/vulnerable-python/`（Flask 应用 + CLI 脚本，含命令注入 / SQL 注入 / 路径穿越 / 硬编码密钥）。

1. 打开前端首页 → 点击右上角 **「内置样本」**（自动填好本地路径）→ **创建并开始审计**；
   - 或点击已存在样本项目上的 **「开始审计」**。
2. 进入**审计控制台**，实时观察各智能体（规模评估 → 编排官 / 侦察员 / 漏洞猎手 / 污点追踪员 / 环境构建官 / 验证官 / 报告官）协同工作的时间线（含模型思考过程）。
3. 审计完成后：
   - **漏洞列表**：每条带严重度（CVSS）与置信度徽章；
   - 点击任一漏洞 → **证据链抽屉**：位置 → 污点路径(source→sink) → 可达性 → 静态/动态验证（若 Docker 可用，CLI 命令注入会显示**沙箱实际复现日志**，置信度为「已动态复现」）；
   - 右上角 **「审计报告」** → 导出 **Markdown / JSON / SARIF**。

> 若装有 Docker，样本中的 `vuln_cli.py` 命令注入会被真实复现（沙箱内注入 `; echo <marker>` 并命中判据）。

---

## 5. 审计自有项目

首页 **「新建项目」**：

- **Git URL**：`https://` 仓库地址（浅克隆；已做 SSRF 防护，禁止内网/非 http(s)）。
- **本地路径**：服务器上代码库的**绝对路径**。

选择审计深度：

| 档位 | 说明 |
|---|---|
| `fast` | 仅静态验证、跳过沙箱 —— 快速体检 / CI 门禁 |
| `standard`（默认） | 静态验证 + 对可复现类做沙箱 PoC（不搭建常驻环境） |
| `deep` | 追加**环境构建官**（搭建目标应用 + 核验预热）与**验证官 agentic 深度核验/实弹复现** + 更大预算 |

支持语言：Python / JavaScript·TypeScript / Java / Go / PHP（可扩展）。

---

## 6. 云端强模型模式

编辑 `backend/.env`：

```ini
VERIAUDIT_LLM_PROVIDER=anthropic
VERIAUDIT_LLM_API_KEY=sk-...           # 你的云端模型 API Key
VERIAUDIT_MODEL_STRONG=claude-opus-4-8 # 发现/追踪/验证（推理核心）
VERIAUDIT_MODEL_CHEAP=claude-haiku-4-5 # 侦察/报告
```

重启后端即生效。此时：漏洞猎手会调用 LLM 阅读代码做**语义高召回发现**，验证官用 LLM 做**独立静态复核**并生成针对性 PoC 与修复建议。经 LiteLLM 抽象，可替换为任意受支持的云端模型（OpenAI / DeepSeek / Qwen 等）。**本地模型接口已预留（`local` provider 占位），本期不实现。**

> 密钥仅服务端加载，**永不下发前端、永不进沙箱**（见 `docs/08-security-threat-model.md`）。

---

## 7. 生产部署（单端口一体化）

前端构建产物可由后端直接托管：

```bash
cd frontend && npm run build      # 生成 frontend/dist
cd ../backend && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

后端检测到 `frontend/dist` 后会在 `/` 挂载静态站点 —— 直接访问 `http://<host>:8000` 即可（API 与前端同源，无需代理）。

> 生产环境建议：置于 Nginx 反向代理之后；`api` 与编排 `worker` 拆分为独立进程/队列（当前 MVP 为单进程 asyncio 编排，见 `docs/01` §4）；开启鉴权与预算护栏。

---

## 8. 环境变量速查

| 变量（前缀 `VERIAUDIT_`） | 默认 | 说明 |
|---|---|---|
| `DATABASE_URL` | SQLite | 数据库连接串 |
| `LLM_PROVIDER` | `openai` | LiteLLM provider 标签 |
| `LLM_API_KEY` | 空 | 空=Mock 模式；非空=云端模式 |
| `LLM_API_BASE` | 空 | 自建/中转 base url（可选） |
| `MODEL_STRONG/MID/CHEAP` | opus/opus/haiku | 分角色模型 |
| `ENABLE_SANDBOX` | `true` | 是否启用 Docker 动态验证 |
| `SANDBOX_TIMEOUT_SEC` | `60` | 单次利用请求窗口超时 |
| `SANDBOX_BUILD_TIMEOUT_SEC` | `420` | 复现容器总超时（含装依赖+启动） |
| `SANDBOX_ALLOW_NETWORK` | `true` | 复现容器放开网络（仅用于装项目依赖；设 `false` 走严格无出网，则只有依赖已内置的项目可复现） |
| `ENABLE_PROVISIONER` | `true` | 是否启用环境构建官（仅 `deep` 档生效：一次把目标应用搭起来供复用） |
| `ENABLE_PROVISIONER_PREHEAT` | `true` | **核验预热**：应用起来后，由模型按项目自适应地准备可复用的验证基底（测试账号、按角色登录的会话、seed 数据、备忘），让逐候选核验热启动、少走冤枉步数。**已取代** `PROVISIONER_LLM_ENRICH` |
| `PREHEAT_MAX_STEPS` | `14` | 预热阶段工具步数上限（自适应下限） |
| `PROVISIONER_LLM_ENRICH` | `false` | （已被预热取代，保留仅作兼容/关闭用） |
| `ENABLE_ADAPTIVE_BUDGET` | `true` | **规模自适应预算**（见下）。开启时下面各上限被当作**小项目的下限**，审计前由评估模块按项目规模/复杂度自动放大；设 `false` 则退回下面的固定值 |
| `PROVISIONER_MAX_STEPS` / `PROVISIONER_TIMEOUT_SEC` | 16 / 900 | 搭建步数与总时长预算（自适应下限；防死循环/控 token） |
| `PROVISIONER_CMD_TIMEOUT_SEC` | `240` | 单条搭建命令超时（自适应下限；需构建的项目会自动放大） |
| `ENABLE_SEMGREP` / `ENABLE_SECRET_SCAN` / `ENABLE_DEPENDENCY_SCAN` | `true` | 专业工具（Semgrep / Gitleaks / OSV）开关 |
| `ENABLE_CODEQL` | `false` | CodeQL 语义分析扫描（重，深度档；需安装 codeql） |
| `ENABLE_CODEQL_CALLGRAPH` | `true` | 调用图精度阶梯之首：CodeQL 精化跨过程调用边(**已实现并验证:python / javascript / typescript**;免构建、精度高)。吃内存(~1.4GB)可能 OOM 降级,机器紧张可设 `false` |
| `CODEQL_RAM_MB` / `CODEQL_TIMEOUT_SEC` | 1400 / 300 | CodeQL 建库/查询的内存上限与超时 |
| `ENABLE_JOERN_CALLGRAPH` | `true` | 阶梯第二级：Joern 多语言调用图(**已验证:PHP / Go / Python**;Java/JS 前端就绪)。**免构建**——含 Go 等编译型语言直接解析源码,无需编译。需 joern-cli + JDK17+(自动探测 `D:/Tools`);PHP/JS/Go 前端另需 `php`/`node`/`go` |
| `JOERN_DIR` / `JOERN_JAVA_HOME` / `JOERN_TIMEOUT_SEC` | 自动 / 自动 / 420 | joern-cli 目录、JDK17+ 路径(留空自动探测 D:/Tools)、单步超时 |
| `LLM_HUNT_STEPS` | `16` | LLM 主导挖掘的最大工具步数（自适应下限；控 token） |
| `LLM_TRIAGE_LIMIT` | `16` | LLM 验证判定的候选上限（自适应下限；控 token） |
| `ENABLE_AGENTIC_VERIFY` | `true` | **深度核验**：验证官自主读全上下文 + 在常驻应用上用专业工具实弹复现（仅 deep + 已搭建环境时可用） |
| `VALIDATOR_AGENTIC_FIRST` | `true` | 核验策略：`true`=**agentic 优先**（对每个符合条件的候选先做 agentic 深度核验，失败才回落旧的单轮判定）；`false`=**旧逻辑优先**（默认走单轮判定，仅高危/严重+可复现的候选才升级 agentic） |
| `ENABLE_AGENTIC_VERIFY_LIMIT` | `false` | 是否启用深度核验的名额配额。默认 `false`=**不限名额**（每个符合条件的候选都做 agentic 深度核验，更彻底但更耗 token）；设 `true` 才用 `AGENTIC_VERIFY_LIMIT` 封顶 |
| `AGENTIC_VERIFY_LIMIT` | `3` | 每任务进入深度核验的候选数上限（自适应下限；**仅当 `ENABLE_AGENTIC_VERIFY_LIMIT=true` 时生效**，按严重度优先分配） |
| `VALIDATOR_STEPS` | `12` | 每候选深度核验的**基准步数 B**（自适应下限）。实际每候选步数 = B + 附加(位次/漏洞类别/是否鉴权/污点深度) |
| `VALIDATOR_STEP_ADD_MAX` / `VALIDATOR_STEP_HARD_CAP` | 12 / 40 | 附加值封顶 / 单候选步数绝对硬顶（控最坏成本） |
| `VALIDATOR_STEP_EXTENSION` | `1.5` | 会话接近复现成功却将耗尽步数时，一次性把上限提到 `1.5×` 计划步数（受硬顶约束） |
| `VALIDATOR_STEPS` | `12` | 单个候选深度核验的工具步数上限（自适应下限；鉴权类复现需要更多步） |
| `LLM_TIMEOUT_SEC` / `LLM_NUM_RETRIES` | 90 / 1 | LLM 请求超时与重试（自适应下限；防挂起） |
| `MAX_CANDIDATES` / `MAX_VERIFY` | 60 / 30 | 预算护栏（自适应下限） |
| `TASK_TIMEOUT_SEC` | `1800` | 单任务总超时（自适应下限；自动放大以覆盖各阶段预算之和） |
| `CORS_ORIGINS` | `*` | 允许的跨域来源 |

> **规模自适应预算（`app/profiler.py`）**：每次审计开始前，先由「规模评估」阶段（前端时间线第一个环节）扫描项目的**文件数、代码行、入口点、语言数、依赖数，以及是否需要构建工具链 / 数据库 / 多服务**，据此把上表所有上限从「下限（小项目）」线性放大到内置上限。这样 5 文件的样本与 400 文件的多语言应用不会共用同一套步数/超时——小项目快而省，大项目有足够预算跑完工作而不会中途被掐断（这正是「猎手没产出候选 / 搭建官搭到一半被停」的根因）。评估结果与算出的预算会实时显示在前端时间线。

### 专业审计工具（真实人员常用；自动探测，缺失即降级）

VeriAudit 的漏洞猎手（LLM）可**自主调用**以下专业工具（各司其职、不重复）。将它们的可执行文件放入 PATH 即自动启用（`/api/v1/config` 的 `scanners` 字段显示可用性）：

| 工具 | 职责 | 安装 |
|---|---|---|
| **Semgrep** | 多语言模式 SAST（广度） | `pipx install semgrep`（离线自动回落到内置 Bandit） |
| **CodeQL** | 语义数据流分析（精度，深度档） | 下载 CodeQL CLI，置于 PATH，并设 `ENABLE_CODEQL=true` |
| **Gitleaks** | 硬编码密钥/凭据 | 下载 gitleaks 二进制 |
| **OSV-Scanner** | 依赖已知 CVE（SCA） | 下载 osv-scanner 二进制 |

**验证官的动态核验/复现工具**（deep 档、环境已搭建时可用；已预装在沙箱镜像 `veriaudit-sandbox-env-*` 内，无需宿主安装）：

| 工具 | 职责 |
|---|---|
| **http_probe** | 向常驻应用发精确请求复现漏洞，自动带 Cookie（可先登录再打受鉴权接口） |
| **sqlmap** | SQL 注入的确认/利用（含盲注/时间盲注） |
| **nuclei** | 模板化验证配置/暴露类问题（CORS 错配、路径遍历、调试端点暴露等） |
| **strace** | 运行时系统调用观测（是否真的 `open('/etc/passwd')` / `execve('/bin/sh')`） |
| **sql_log** | 白盒 SQL 观测：开启 MySQL 通用日志，看 payload 产生的真实 SQL（盲注/二阶注入的决定性证据） |
| **mysql 客户端** | 查/建/seed 数据、为受鉴权接口创建测试账号 |

> 云端模式下，模型依据审计方法论**自行决定**调用哪些工具；无任何工具时仍可仅凭 LLM 阅读代码 + 内置规则完成审计。**模型的思考过程与结构化输出会实时显示在前端时间线**，便于追溯漏洞挖掘全过程。

---

## 8.5 调用图精度：如何让 CodeQL / Joern 命中（按待审语言配置）

跨过程可达性走**精度阶梯**：`CodeQL > Joern > Tree-sitter > 文件启发式`。Tree-sitter 是"能跑但按名解析、精度有限"的兜底——**我们一般不希望走到它**。要让 CodeQL/Joern 命中，需按**待审计项目的语言**准备好对应环境；**未命中会自动降级，并在前端弹出醒目的"能力降级提示"**（不会静默）。

> ⚠️ 现实约束：无法保证对任意开源项目都命中。本表列出命中所需的前置条件；缺失即降级到 Tree-sitter。

**一次性前置（无论什么语言）**
- **CodeQL**（给 Python / JavaScript / TypeScript 高精度）：安装 CodeQL CLI，置于 PATH；`ENABLE_CODEQL_CALLGRAPH=true`（默认）。约需 1.4GB 空闲内存。
- **Joern**（覆盖其余语言，免构建）：需 `joern-cli` + **JDK 17+**。默认自动探测 `D:/Tools/joern-cli` 与 `D:/Tools/jdk-2x`；否则设 `JOERN_DIR` / `JOERN_JAVA_HOME`。`ENABLE_JOERN_CALLGRAPH=true`（默认）。部分前端（如 PHP）峰值需约 4GB 内存。
- **外部前端工具必须在"启动后端的那个 shell 的 PATH"上**（后端进程继承该 PATH）；否则对应语言的 Joern 前端会失败降级。

**按待审计项目语言**

| 项目语言 | 命中引擎 | 除上面外，还需安装 | 是否需编译 | 验证状态 |
|---|---|---|---|---|
| Python | CodeQL | 无（CodeQL 直接解析） | 否 | ✅ 已验证（调用图 + 污点数据流） |
| JavaScript / TypeScript | CodeQL | 无（CodeQL 直接解析，TS 复用 js 提取器；**不需要 Node**） | 否 | ✅ 已验证（调用图 + 污点数据流，靶例 source→sink 命中） |
| Java | Joern | 无（javasrc2cpg 纯 JVM，用 JDK17+ 即可，**不需要项目自己的 JDK**） | 否 | 前端就绪，未跑真实项目 |
| Go | Joern | **Go 工具链**（`go` 在 PATH） | **否**（直接解析源码） | ✅ 已验证 |
| PHP | Joern | **PHP CLI**（`php` 在 PATH；本机已装 `D:/Tools/php` 并自动加入） | 否 | ✅ 已验证 |
| Ruby | Joern | 无 | 否 | CodeQL 支持但其数据流库在有限内存下编译过重、且暂无验证靶例，故留给 Joern；未验证 |
| C / C++ | Joern | 无（c2cpg 纯 JVM，模糊解析；精度视头文件而定） | 否 | 未验证 |
| C# | Joern | **.NET SDK**（`dotnet` 在 PATH） | 否 | 未验证 |
| Kotlin | Joern | 可能需 Kotlin | 否 | 未验证 |

**配置本系统（相关环境变量，详见第 7 节表）**
- `ENABLE_CODEQL_CALLGRAPH` / `ENABLE_JOERN_CALLGRAPH`：两级开关（默认开）。
- `JOERN_DIR` / `JOERN_JAVA_HOME`：joern-cli 目录与 JDK17+（留空自动探测 `D:/Tools`）。
- `CODEQL_RAM_MB` / `CODEQL_TIMEOUT_SEC` / `JOERN_TIMEOUT_SEC`：内存与超时（内存不足或超时会降级）。

**智能体查看调用图的方式**（导航式、有界、带 file:line 锚点，猎手/验证官按需调用）：`cg_overview`（攻击面概览）、`cg_callers`/`cg_callees`（谁调它/它调谁，带调用点行号，`offset` 翻页）、`cg_reachable`（危险点是否可从入口到达 + 入口→sink 链 + 有几个入口可达）、`cg_path`（两点调用链）、`cg_subgraph`（某函数周围 N 跳子图）、`cg_dataflow`（**污点数据流**：判断污点是否真的从 source 流到 sink，比"控制可达"更强更准；走 **CodeQL>Joern 阶梯**——Python / JavaScript / TypeScript 用 CodeQL 语义污点、其余语言用 Joern `reachableByFlows`；较重、按需少量用）。每个结果都带"图可能有错/缺边、不可达≠安全、务必 read_file 核实"的显式提示。

**降级会怎样提示**：一旦命中的引擎低于该语言的理想引擎（如 Python 没走到 CodeQL、Go/PHP 没走到 Joern），前端审计控制台顶部会显示**"能力降级提示"横幅**，并给出**具体原因与解决办法**（缺 codeql / 缺 JDK17+ / 缺 php·node·go / 内存不足 / 已被开关关闭）。同理，**LLM Mock 模式、Docker 不可用、专业扫描器缺失**等降级也会在此横幅醒目提示，避免误以为系统在满血运行。

---

## 9. 目录结构

```
VeriAudit/
├─ README.md                 项目定位与文档索引
├─ LAUNCH.md                 本文件
├─ docs/                     系统设计文档（01~09）
├─ samples/                  内置漏洞样本（演示用）
├─ backend/
│  ├─ requirements.txt
│  ├─ .env.example
│  ├─ app/
│  │  ├─ main.py             FastAPI 入口（REST + SSE）
│  │  ├─ config.py db.py models.py schemas.py events.py workspace.py
│  │  ├─ knowledge.py analysis.py sandbox.py severity.py report.py
│  │  ├─ profiler.py         规模评估：按项目复杂度计算各阶段预算上限
│  │  ├─ orchestrator.py     评估 + 七阶段编排状态机
│  │  ├─ llm/gateway.py      LiteLLM 网关（+ Mock 回落，含步数将尽的收尾提示）
│  │  ├─ agents/             planner/recon/hunter/tracer/provisioner/validator/reporter
│  │  │                       + tools（挖掘）/verify_tools（深度核验+动态复现）/provision_tools/prompts/context
│  │  └─ api/routes.py       REST + SSE 路由
│  └─ scripts/smoke.py       离线端到端冒烟测试
└─ frontend/
   ├─ src/pages/             Projects / TaskConsole
   ├─ src/components/        Timeline / EvidenceChain / Badge / StatCard / ReportModal / Layout
   └─ src/lib/               useTaskEvents(SSE) / format(语义色)
```

---

## 10. 冒烟自测（无需前端）

后端可离线自测整条流水线：

```bash
cd backend
.venv\Scripts\python.exe scripts\smoke.py      # Windows
# ./.venv/bin/python scripts/smoke.py          # macOS/Linux
```

预期输出 5 条 findings（命令注入 ×2 / SQL 注入 / 路径穿越 / 硬编码密钥）并打印 `SMOKE OK`。

---

## 11. 常见问题

| 现象 | 处理 |
|---|---|
| 前端能打开但接口 500/无数据 | 确认后端已在 `:8000` 运行（`/healthz`）；查看后端终端日志 |
| 侧栏显示「沙箱不可用」 | 未装/未启动 Docker，或 `ENABLE_SANDBOX=false`；不影响静态审计 |
| 动态验证总是「未复现」 | 目标非自包含 CLI 入口时会安全跳过（静态结论有效）；这是预期行为 |
| 首次动态验证/搭建很慢 | 首次会基于本地 `python:3.11-slim` 构建一个预装通用工具链（gcc/make/git/curl/wget/unzip）的搭建镜像 `veriaudit-sandbox-env`（约 1~2 分钟，一次性），之后缓存复用；不自动拉取新基础镜像以省 C 盘 |
| 搭建官装不上 php/mysql 等运行时 | 搭建容器已放开 apt/dpkg 所需的最小权限集（保持 cap-drop ALL + 仅按需 cap-add）；模型可直接 `apt-get install` 语言运行时/数据库。若仍失败，检查 `SANDBOX_ALLOW_NETWORK=true`（装包需出网） |
| Git 克隆失败 | 仅允许 http/https 公网仓库；内网/`file://` 被 SSRF 防护拒绝 |
| Python 版本较低报语法错误 | 需 Python ≥ 3.9 |

---

## 12. 安全声明

VeriAudit 会**克隆并分析不可信代码**、在沙箱中**执行 LLM 生成的利用代码**。请仅在**授权范围内**对目标进行安全测试。系统自身的威胁模型与防护（提示注入、沙箱隔离、SSRF、密钥保护、无默认弱口令等）见 [`docs/08-security-threat-model.md`](docs/08-security-threat-model.md)。
