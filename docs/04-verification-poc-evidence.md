# 04 · 验证、PoC 与证据链

这是 VeriAudit 的**核心竞争力所在**。本文定义：双层验证流水线、沙箱与 PoC 自动生成、置信度分级，以及贯穿全系统的**证据链数据模型**。

---

## 1. 双层验证流水线

一个候选漏洞（Candidate）要成为报告中的确认漏洞（Finding），必须通过验证。VeriAudit 采用**双层**验证，因为单靠沙箱 PoC 会漏掉大量跑不出复现的逻辑类漏洞。

```
候选 Candidate（Hunter 高召回产出，带自评置信度）
      │
      ▼  ── 第 0 层：可达性闸门（Tracer） ──
  reachability_check：从不可信入口点是否可达该 sink？
      ├─ 不可达 ─────────────────────────▶ REJECTED（记为已排除，进评估集）
      └─ 可达 / 条件可达
      │
      ▼  ── 第 1 层：静态数据流验证（Validator，独立上下文） ──
  · 以 source/sink/污点路径为线索，独立重判
  · 检查净化器：路径上是否有有效转义/参数化/校验
  · 判定：污点确实从 source 无净化地到达 sink？
      ├─ 证据不足 ─▶ request_more_context（回退 Tracer/Hunter，≤N 轮）
      ├─ 被证伪 ───▶ REJECTED
      └─ 成立
      │
      ▼  ── 第 2 层：动态沙箱 PoC 验证（Validator，可选/按类型） ──
  可复现类（注入/反序列化/路径穿越/SSRF/XXE 等）：
    sandbox_build → 起服务 → 生成 PoC → run_poc → 观测
      ├─ 复现成功 ─▶ CONFIRMED_DYNAMIC（最高置信）
      ├─ 复现失败(N次自我纠错后) ─▶ 回落到第 1 层结论
  难复现类（越权/认证绕过/业务逻辑）：
    跳过动态层，采用第 1 层的静态结论
      │
      ▼
  固化 Finding + EvidenceChain + 置信度 + CVSS
```

**设计要点**
- **第 0 层是最便宜也最有效的降误报闸门**：不可达直接排除，不浪费 LLM/沙箱资源。
- **第 1 层用全新上下文独立复核**，不信任发现阶段的结论（对应 [`02`](02-agents-and-orchestration.md) 原则一）。
- **第 2 层按漏洞类型选择性触发**——不是所有漏洞都强行跑沙箱。
- **REJECTED 不丢弃**：保留用于报告"已排除项"与评估集回归（区别于一般工具"扫完即弃"）。

---

## 2. 置信度分级

拒绝二元结论，采用四级置信度，报告中明确标注，让使用者据此决定人工复核优先级：

| 置信度 | 含义 | 触发条件 |
|---|---|---|
| **CONFIRMED_DYNAMIC** | 已动态复现 | 沙箱中 PoC 成功触发漏洞，有请求/响应/日志为证 |
| **CONFIRMED_STATIC** | 数据流已确证 | 可达 + 污点路径完整无有效净化 + 静态验证成立（适用难复现的逻辑类） |
| **SUSPECTED** | 疑似，需人工复核 | 可达但证据链有缺口（如跨过程分析不确定），或净化器有效性存疑 |
| **REJECTED** | 已排除 | 不可达 / 被证伪 / 存在有效净化 |

> 报告默认只呈现 `CONFIRMED_*` 与 `SUSPECTED`；`REJECTED` 收纳在"已排除项"附录中，体现审计的完整性与可信度。

---

## 3. 沙箱与 PoC 自动生成

### 3.1 沙箱环境构建
由语言适配器的 `sandbox_recipe` 驱动（见 [`01`](01-architecture.md) §6）：

```
sandbox_build 流程：
  1. 拉起一次性容器（seccomp + 只读根 + 无出网 + 资源限额 + 非root）
  2. 挂载目标代码（只读）
  3. 按 recipe 安装依赖、启动目标服务（若为 Web 类）
  4. 返回 sandbox_id + 内部 service_url + 构建日志
```

### 3.2 PoC 自动生成与自我纠错循环

```
Validator 生成 PoC：
  ┌─ 依据 vuln_type + 证据链 + kb_search(该类漏洞利用手法) 生成 poc_spec
  │  （poc_spec = 利用请求/脚本 + 预期可观测判据 oracle）
  ▼
  run_poc(sandbox_id, poc_spec)
  ├─ oracle 命中（如命令回显、报错泄露、越权数据返回）─▶ 复现成功
  └─ 未命中 ─▶ 分析 stdout/stderr/response → 改写 poc_spec → 重试
                （最多 N 次，N 可配；每次改写记录到时间线）
  超过 N 次仍失败 ─▶ 回落第 1 层静态结论，置信度降为 CONFIRMED_STATIC/SUSPECTED
```

**Oracle（判据）设计**：每类漏洞定义"复现成功"的可观测信号，例如：
- 命令注入：注入 `id` 后响应/日志出现 `uid=`；
- SQL 注入：布尔盲注真假分支响应差异，或报错型注入的数据库报错；
- 路径穿越：读到 `/etc/passwd` 特征串；
- SSRF：沙箱内起一个金丝雀服务，目标回连即命中（**金丝雀在沙箱内网，绝不出网**）。

### 3.3 产物固化
PoC 代码、成功的请求/响应、沙箱日志、金丝雀命中记录等一并落对象存储，作为证据链的 `artifacts`，可在报告与前端逐项查看/下载。

---

## 4. 证据链数据模型（EvidenceChain）

证据链是 VeriAudit 的一等对象——不是报告里的一段话，而是结构化、可视化、可导出、可追溯的数据。

```python
class CodeLocation(BaseModel):
    file: str
    line: int
    col: int | None
    function: str | None
    snippet: str            # 定位处代码片段

class TaintHop(BaseModel):
    location: CodeLocation
    variable: str           # 被污染的变量/表达式
    transform: str | None   # 该跳发生的处理（拼接/编码/传参...）
    note: str | None        # LLM 对该跳的说明

class EvidenceChain(BaseModel):
    finding_id: str
    vuln_type: str          # CWE 编号 + 名称，如 "CWE-89 SQL Injection"

    # —— 攻击面与污点两端 ——
    entry_point: CodeLocation          # 不可信入口（HTTP 路由/CLI/消费者...）
    source: CodeLocation               # 污点源（用户可控输入）
    sink: CodeLocation                 # 危险汇聚点

    # —— 传播路径 ——
    taint_path: list[TaintHop]         # source → ... → sink 有序各跳
    sanitizers_checked: list[dict]     # 路径上检查过的净化器及其是否有效

    # —— 可达性 ——
    reachability: dict                 # {reachable, entry_points, preconditions, confidence}

    # —— 静态验证 ——
    static_verdict: dict               # {status, rationale, model, checked_at}

    # —— 动态验证 ——
    dynamic_verification: dict | None  # {attempted, reproduced, poc_ref,
                                       #  sandbox_run_ref, oracle_hit, observation}

    # —— 结论 ——
    confidence: str                    # CONFIRMED_DYNAMIC | CONFIRMED_STATIC | SUSPECTED
    artifacts: list[dict]              # PoC/请求响应/日志/截图 引用
```

**证据链回答的四个问题**（也是前端可视化的四段）：
1. **在哪**：entry_point / source / sink 的文件位置；
2. **怎么到的**：taint_path 逐跳的调用路径与数据传播；
3. **为什么成立**：sanitizers_checked（哪些净化被绕过/缺失）+ reachability；
4. **凭什么信**：static_verdict + dynamic_verification（PoC 复现产物）。

---

## 5. 与严重度、报告的衔接

- 证据链要素（是否可达、是否需认证、影响范围、是否已复现）直接喂给 `cvss_score` 推导 CVSS v3.1 向量与分级（见 [`06`](06-report-design.md)）。
- 每个 Finding 在报告中呈现为：`标题 + 严重度 + 置信度 + 证据链（四段可视化）+ PoC + 修复建议`。

---

## 6. 为什么这套设计"不低于 DeepAudit"

| 关注点 | 保障 |
|---|---|
| 能挖到 | Hunter 高召回（SAST 候选池 + LLM 语义 + 知识库），覆盖注入/反序列化/越权/SSRF/XXE/路径穿越等主流类型 |
| 误报低 | 可达性闸门 + 独立静态验证双重过滤 |
| 有 PoC | 沙箱自动构建 + PoC 自我纠错生成，产出可运行利用代码 |
| 可追溯 | 证据链一等对象，四段式完整呈现 |
| 诚实 | 置信度分级 + 已排除项，不夸大结论 |
