# LAUNCH · 全新 Windows 电脑满血部署指南

本指南带你在**一台全新的 Windows 电脑**上，把 VeriAudit **满血**部署并运行到**与当前这台机器一致的状态**。照着 §1 → §7 从上到下做即可。

VeriAudit 是多智能体代码安全审计与验证系统，前后端分离：
- **后端** `backend/` — Python + FastAPI（智能体编排、工具、双层验证、Docker 沙箱、报告）
- **前端** `frontend/` — React + TypeScript + Vite（实时控制台、证据链、报告导出）

> **“满血”= `/api/v1/config` 全绿**：`mock_mode:false`、`sandbox_available:true`、`scanners` 四项全 `true`、`callgraph.codeql/joern` 全 `true`、`rag_available:true`，且审计以 `deep` 深度运行。此时 LLM 语义发现 + Semgrep/CodeQL/Gitleaks/OSV + 逻辑启发式 + CodeQL/Joern 污点数据流 + Docker 沙箱实弹复现 + RAG 真语义检索 + 环境构建官全部在线。任一项为 `false`，见 §6 对照补齐。

**硬件 / 系统要求**

| 项 | 要求 | 说明 |
|---|---|---|
| OS | Windows 10 / 11 (x64) | 本指南按 Windows 编写；外部引擎走 `D:/Tools` 自动探测 |
| 内存 | **≥ 16 GB** | CodeQL ~2 GB、Joern（PHP 前端峰值 ~4 GB）、污点追踪 4 路并行各 ~1.4 GB；不足会自动降级（前端提示） |
| 磁盘 | ≥ 20 GB 空闲 | 约定大件全落 **D 盘**（`D:/Tools/*`），C 盘保持干净 |
| 网络 | 需联网 | 云端模型 API、沙箱装依赖、fastembed 首次下载模型（均一次性/按需） |

---

## 1. 依赖总表（精确版本 · 安装位置 · 配置）

这是**唯一权威清单**。版本列为**本机满血实测**的一套（复现当前状态即照此版本）；安装位置遵循 D 盘约定。**关键铁律**：带“PATH”的工具必须出现在**启动后端那个终端的 PATH** 上——后端进程继承该 PATH 才能调用它们；带“自动探测”的放到指定目录即可、无需入 PATH。

| # | 组件 | 版本 | 下载来源 | 安装到 | 配置 | 解锁 |
|---|---|---|---|---|---|---|
| 1 | Python | **3.9.13** (≥3.9) | python.org | 任意 | 勾选 Add to PATH；后端用 `.venv` | 后端运行时 |
| 2 | Node.js | **24.15.0** / npm 11.12.1 (≥18 LTS) | nodejs.org | 默认 | 安装器自动入 PATH | 前端 + Joern 的 JS/TS 前端 |
| 3 | Docker Desktop | **29.5.2** (≥20) | docker.com | 默认 | 装后预拉镜像（见 §2-Step2） | 沙箱动态复现 / 环境构建官 |
| 4 | CodeQL (codeql-bundle) | **2.25.6** (≥2.15) | github.com/github/codeql-action/releases → `codeql-bundle-win64.tar.gz`（含 CLI+查询库） | `D:/Tools/codeql-bundle/` | **PATH** 加 `D:/Tools/codeql-bundle/codeql` | Python/JS/TS 高精度调用图+污点+`codeql_scan` |
| 5 | Joern CLI | 最新稳定 release | github.com/joernio/joern/releases → `joern-cli.zip` | `D:/Tools/joern-cli/` | 自动探测（或 `VERIAUDIT_JOERN_DIR`） | 其余语言免构建调用图/污点 |
| 6 | JDK（给 Joern） | **Temurin OpenJDK 21.0.11+10 LTS** (≥17) | adoptium.net | `D:/Tools/jdk-21.0.11+10/` | 自动探测（目录名须 `jdk-17/18/19/2x` 开头；或 `VERIAUDIT_JOERN_JAVA_HOME`） | Joern 运行时 |
| 7 | Semgrep | **1.168.0** | `pipx install semgrep` | pipx 管理（`D:/Tools/pipx`） | **PATH**（pipx 自动配）；缺失自动回落内置 Bandit | 多语言模式 SAST |
| 8 | Gitleaks | **8.30.1** | github.com/gitleaks/gitleaks/releases | `D:/Tools/gitleaks/` | **PATH** 加该目录 | 硬编码密钥扫描 |
| 9 | OSV-Scanner | **2.4.0** | github.com/google/osv-scanner/releases | `D:/Tools/osv-scanner/` | **PATH** 加该目录 | 依赖已知 CVE (SCA) |
| 10 | PHP CLI（审 PHP 才需） | **8.5.8 NTS x64** (≥7.4) | windows.php.net/download（Non-Thread-Safe x64） | `D:/Tools/php/` | 系统**自动**把 `D:/Tools/php` 注入后端 PATH | Joern 的 PHP 前端 |
| 11 | Go（审 Go 才需） | **1.24.11** | go.dev/dl | 默认 | 安装器自动入 PATH | Joern 的 Go 前端 |
| 12 | 云端模型 Key | — | 你的云服务商 | 写进 `backend/.env` | `VERIAUDIT_LLM_API_KEY=...` | 退出 Mock，进入满血 |

> **fastembed（RAG 真语义）** 无需单独装：它随 `pip install -r requirements.txt`（0.7.4）装好；**首次**建语义索引时自动把模型 `BAAI/bge-small-en-v1.5` 下载到 `D:/Tools/fastembed_cache`（联网一次，之后离线）。缺它则 RAG 回落词法 hashing（会弹降级提示）。

**当前机器的 `D:/Tools/` 参考布局**（照此复现即可）：

```text
D:/Tools/
├─ codeql-bundle/        # 4  → PATH: D:/Tools/codeql-bundle/codeql
├─ joern-cli/            # 5  → 自动探测
├─ jdk-21.0.11+10/       # 6  → 自动探测
├─ gitleaks/             # 8  → PATH
├─ osv-scanner/          # 9  → PATH
├─ php/                  # 10 → 自动注入（审 PHP）
├─ pipx/  semgrep-cache/ # 7  → semgrep（pipx）
└─ fastembed_cache/      #    → RAG 模型缓存
```

**后端 Python 依赖版本**（`requirements.txt` 为 `>=` 下限；括号=本机实测，需严格复现可 `pip install 包==版本`）：
fastapi(0.128.8)、uvicorn[standard](0.39.0)、sqlalchemy(2.0.51)、pydantic(2.12.5)、pydantic-settings、litellm(1.83.9)、python-multipart、jinja2、bandit(1.8.6)、tree-sitter(0.23.2)、tree-sitter-language-pack(0.9.1)、numpy(2.0.2)、fastembed(0.7.4)。

---

## 2. 安装步骤（照做）

**Step 1 · 语言运行时**
装 Python 3.9.x（勾 *Add python.exe to PATH*）、Node.js LTS。新开终端验证：`python --version`、`node --version`。

**Step 2 · Docker + 基础镜像**
装 Docker Desktop 并启动，然后预拉镜像（系统**不自动拉基础镜像**以省 C 盘）：
```powershell
docker pull python:3.11-slim   # 沙箱/搭建基础镜像（~189MB，必需）
docker pull node:20-slim       # 审 JS/TS 项目时的沙箱 CLI 镜像（按需）
```

**Step 3 · D:/Tools 外部引擎 + PATH**
按 §1 表把 #4–#11 解压到对应 `D:/Tools/` 子目录，然后把这些目录加入 **系统环境变量 Path**：
```text
D:/Tools/codeql-bundle/codeql
D:/Tools/gitleaks
D:/Tools/osv-scanner
（审 Go 才加）Go 的 bin 目录
```
（Joern / JDK / PHP 走自动探测，**不必**入 PATH。）改完 Path **必须新开终端**才生效。

**Step 4 · Semgrep（可选但推荐）**
```powershell
python -m pip install --user pipx ; python -m pipx ensurepath
pipx install semgrep
```
> Semgrep 对 Windows 原生支持有限；装不上不影响满血其余项，会自动回落内置 Bandit 出候选。

**Step 5 · 验证外部工具在 PATH**
新开终端逐条执行，应各自打印版本号：
```powershell
codeql --version ; gitleaks version ; osv-scanner --version ; semgrep --version
```

**Step 6 · 准备云端模型 Key**（§4 填入 `.env`）。

---

## 3. 启动后端与前端

**后端**（必须在“已配好 PATH 的终端”里启动，才能继承并调用外部引擎）：
```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# 满血基线：.env.example 已把 CODEQL/JOERN/RAG/SANDBOX/PROVISIONER 全开、不限深度核验名额、放开沙箱网络
copy .env.example .env
#   编辑 backend\.env：填 VERIAUDIT_LLM_API_KEY=<你的 Key>（不填=Mock，非满血）
#   （三档模型默认 deepseek-v4-flash，可按需改；见 §7）

python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**前端**（新开一个终端）：
```powershell
cd frontend
npm install
npm run dev          # http://localhost:5173
```

浏览器打开 **http://localhost:5173**（开发服务器已代理 `/api` 与 `/healthz` 到后端 `:8000`，含 SSE）。

---

## 4. 满血自检（务必确认）

访问 **`http://localhost:8000/api/v1/config`**，应与当前机器一致：

```jsonc
{
  "mock_mode": false,
  "sandbox_available": true,
  "scanners": { "semgrep": true, "codeql": true, "gitleaks": true, "osv": true },
  "callgraph": { "codeql": true, "joern": true },
  "rag_available": true
}
```

任一 `false` → 对照 §1 补齐；最常见原因是**该工具不在后端进程的 PATH 上**（确认在启动后端的终端里 `codeql --version` 等能跑，或改完 Path 后重启终端与后端）。前端首屏「能力读数」也实时显示这些开关。

---

## 5. 开始审计

**内置样本**：仓库自带 `samples/vulnerable-python/`（Flask + CLI，含命令注入/SQL 注入/路径穿越/硬编码密钥）。首屏 **「新建项目」** → 选 **deep** → 创建并开始。

**自有项目**：**「新建项目」** → Git URL（`https://`，已做 SSRF 防护）或本地绝对路径 → 选深度：

| 档位 | 说明 |
|---|---|
| `fast` | 仅静态验证、跳过沙箱（快速体检/CI 门禁） |
| `standard` | 静态验证 + 对可复现类做沙箱 PoC |
| **`deep`（满血推荐）** | 追加环境构建官 + 验证官 agentic 深度核验/实弹复现 + 更大预算 |

审计中可在控制台观察各智能体时间线（含模型思考、工具调用、开始/完成、自适应预算），右上角 ❚❚暂停 / ▶继续 / ■停止（协作式，在阶段边界或下一模型步生效）。完成后：点漏洞看**证据链抽屉**（SOURCE→HOP→SINK / 可达性与验证 / CVSS / PoC / 修复），右上角 **报告** 导出 Markdown/JSON/SARIF。

---

## 6. 调用图精度：按待审语言命中 CodeQL / Joern

跨过程可达性走阶梯 `CodeQL > Joern > Tree-sitter > 文件启发式`（满血不希望走到 Tree-sitter 兜底）。**未命中会自动降级并在控制台顶部弹醒目“能力降级提示”**（含原因与解法）。

**一次性前置**：CodeQL（给 py/js/ts）、Joern + JDK17+（给其余语言）——已在 §1 装好。**外部前端工具须在后端进程 PATH 上**，否则该语言 Joern 前端失败降级。

| 项目语言 | 命中引擎 | 额外需要 | 验证状态 |
|---|---|---|---|
| Python | CodeQL | 无 | ✅ 已验证 |
| JavaScript / TypeScript | CodeQL | 无（TS 复用 js 提取器，不需 Node） | ✅ 已验证 |
| Go | Joern | `go` 在 PATH | ✅ 已验证 |
| PHP | Joern | `D:/Tools/php`（自动） | ✅ 已验证 |
| Java | Joern | 无（用 JDK17+） | 前端就绪 |
| Ruby / C·C++ / C# / Kotlin | Joern | C# 需 `dotnet` | 未验证 |

智能体查看调用图的工具：`cg_overview` / `cg_callers` / `cg_callees` / `cg_reachable`（危险点能否从入口到达 + 入口→sink 链）/ `cg_path` / `cg_subgraph` / `cg_dataflow`（污点数据流，py/js/ts 走 CodeQL、其余走 Joern）。每个结果都带“不可达≠安全、务必 read_file 核实”的提示。

---

## 7. `.env` 关键参数

**满血基线就是 `backend/.env.example` 本身**——复制成 `.env`、填好 `VERIAUDIT_LLM_API_KEY` 即可，其余保持默认即满血。完整清单见该文件内注释；部署时最常关注：

| 变量（前缀 `VERIAUDIT_`） | 满血值 | 说明 |
|---|---|---|
| `LLM_API_KEY` | **需填** | 空=Mock（非满血） |
| `LLM_PROVIDER` / `MODEL_STRONG` / `MODEL_MID` / `MODEL_CHEAP` | deepseek / deepseek-v4-flash ×3 | 经 LiteLLM 可换任意云端模型（见下） |
| `ENABLE_SANDBOX` / `SANDBOX_ALLOW_NETWORK` | true / true | Docker 复现；放开网络以便容器装依赖 |
| `ENABLE_CODEQL` / `ENABLE_CODEQL_CALLGRAPH` / `ENABLE_JOERN_CALLGRAPH` | true | 语义扫描 + 两级调用图 |
| `ENABLE_RAG` / `RAG_EMBED_BACKEND` | true / auto | RAG（有 fastembed 走真语义，否则回落词法） |
| `ENABLE_PROVISIONER` / `ENABLE_AGENTIC_VERIFY` | true / true | 环境构建官 + 验证官深度核验（仅 deep） |
| `ENABLE_ADAPTIVE_BUDGET` | true | 规模自适应预算：按项目大小自动放大各阶段上限 |
| `JOERN_DIR` / `JOERN_JAVA_HOME` | 空=自动探测 D:/Tools | 非默认路径时显式指定 |
| `TRACER_CONCURRENCY` | 4 | 污点追踪并行度（各 ~1.4GB；内存紧可调小） |
| `CODEQL_RAM_MB` | 2048 | CodeQL 内存上限（最低 2048） |

换模型示例（重启后端生效；密钥仅服务端加载，永不下发前端/进沙箱）：
```ini
VERIAUDIT_LLM_PROVIDER=anthropic
VERIAUDIT_LLM_API_KEY=sk-...
VERIAUDIT_MODEL_STRONG=claude-opus-4-8
VERIAUDIT_MODEL_CHEAP=claude-haiku-4-5
```

> 可选：设 `VERIAUDIT_LLM_USAGE_LOG=<路径>` 采集**真实** token 用量到 JSONL（默认关闭、零开销、不存 prompt/response 全文）。

---

## 8. 冒烟自测（无需前端）

```powershell
cd backend
.venv\Scripts\python.exe scripts\smoke.py
```
预期输出 5 条 findings（命令注入 ×2 / SQL 注入 / 路径穿越 / 硬编码密钥）并打印 `SMOKE OK`。

---

## 9. 常见问题

| 现象 | 处理 |
|---|---|
| `/config` 某项为 `false` | 该工具不在**后端进程 PATH** 上：在启动后端的终端确认 `codeql --version` 等能跑；改完系统 Path 要**新开终端并重启后端** |
| 前端弹“能力降级：调用图精度” | 对应语言没命中理想引擎——按横幅补 codeql / JDK17+ / php·go，或内存不足（调小 `TRACER_CONCURRENCY` 或加内存） |
| 首屏「模式」显示 MOCK | `backend\.env` 未填 `VERIAUDIT_LLM_API_KEY` |
| 「沙箱不可用」 | Docker 未启动或 `ENABLE_SANDBOX=false`；不影响静态审计 |
| 首次动态验证/搭建慢 | 首次基于 `python:3.11-slim` 构建搭建镜像（约 1~2 分钟，一次性）；确认已 `docker pull python:3.11-slim node:20-slim` |
| RAG 一直提示回落词法 | 未装 `fastembed` 或首次模型下载失败（需联网到 `D:/Tools/fastembed_cache`） |
| 搭建官装不上运行时 | 需 `SANDBOX_ALLOW_NETWORK=true`（容器装包要出网） |
| Git 克隆失败 | 仅允许 http/https 公网仓库；内网/`file://` 被 SSRF 防护拒绝 |

---

## 10. 安全声明与目录结构

VeriAudit 会**克隆并分析不可信代码**、在沙箱中**执行 LLM 生成的利用代码**——请仅在**授权范围内**测试。系统自身威胁模型见 [`docs/08-security-threat-model.md`](docs/08-security-threat-model.md)。

```text
VeriAudit/
├─ LAUNCH.md / README.md / docs/ / samples/
├─ eval-runs/                评测输出 + normalize_run.py（可选）
├─ backend/
│  ├─ requirements.txt  .env.example(满血基线)
│  └─ app/
│     ├─ main.py config.py db.py models.py schemas.py events.py workspace.py
│     ├─ knowledge.py knowledge_frameworks.py analysis.py sandbox.py severity.py report.py
│     ├─ callgraph.py        调用图/污点数据流（CodeQL/Joern/Tree-sitter 阶梯）
│     ├─ profiler.py orchestrator.py
│     ├─ llm/gateway.py      LiteLLM 网关（+ Mock 回落 + 可选 token 采集）
│     ├─ agents/             planner/recon/hunter/tracer/provisioner/validator/reporter + tools/verify_tools/provision_tools/prompts/context
│     ├─ rag/                splitter/embeddings/indexer/retriever/kb
│     └─ api/routes.py
└─ frontend/src/
   ├─ pages/                 Home / History / TaskConsole（浅色自包含页面）
   ├─ lib/                   vaTheme(设计系统)/motion(动画)/useTaskEvents(SSE)/format/api
   └─ App.tsx main.tsx index.css
```
