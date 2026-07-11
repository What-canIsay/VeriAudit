# 手动调用图 / 数据流 · 交付契约

系统对调用图走精度阶梯 `CodeQL > Joern > Tree-sitter`。无人值守的确定性构建对**大型/复杂项目、编译型语言**成功率不稳定（CodeQL 需正确的构建命令；Joern 前端个别项目会内存爆掉）。

**手动模式**：审计开始前，你**离线**把调用图/数据流建好交给系统；系统直接消费它、跳过自动阶梯。

- **在哪选**：前端「新建项目」表单 / 项目卡片「开始审计」处，勾选 **“手动构建”** 并填一个**绝对路径**。
- **系统自动识别两种交付形态**（无需你选类型）：

| 你给的路径 | 形态 | 覆盖 | 适用 |
|---|---|---|---|
| **CodeQL DB 目录**（含 `codeql-database.yml`） | 活 CodeQL DB | **调用图 + 逐点污点，一体** | CodeQL 支持的语言（java/go/csharp/cpp/ruby/python/js·ts），尤其编译型 |
| **JSONL 文件 / 目录** | 预计算 JSONL | 调用图（+ 可选污点） | **语言无关兜底**（如 **PHP/MacCMS**，用 Joern/任意工具产出） |

> 二者都要求**从被审的同一份源码**构建（系统把结果里的 file:line 对齐到工作区的同名函数）。

---

## A. 活 CodeQL DB（推荐，CodeQL 语言）

CodeQL 数据库就是一个**目录**（`codeql database create` 生成、自动 finalize）。你把这个目录的绝对路径交给系统即可；系统从 `codeql-database.yml` 读出语言，用**内置的该语言查询**（`calls.ql` + `dataflow.ql`）直接对这个活 DB 跑——**调用图和 `cg_dataflow` 都从同一个 DB 出**，不重建、不导 JSONL。

**构建（关键：编译型语言给对构建命令）**
```bash
codeql database create D:\cg\proj-db --language=java   --command="mvn -q -DskipTests compile"
codeql database create D:\cg\proj-db --language=go     --command="go build ./..."
codeql database create D:\cg\proj-db --language=csharp --build-mode=none        # 免构建
codeql database create D:\cg\proj-db --language=cpp    --command="<真实编译命令>"
codeql database create D:\cg\proj-db --language=ruby                            # 解释型，免 --command
codeql database create D:\cg\proj-db --language=python                          # 同上
```

**支持语言 / 内置查询**：`python`、`javascript`（含 TypeScript，DB 的 primaryLanguage 即 javascript）、`java`、`csharp`、`cpp`、`go`、`ruby`。查询在 `backend/app/cg_queries/<lang>/{calls.ql,dataflow.ql}`。**验证状态**：python 端到端实测通过（调用图 + 污点）；java/csharp/cpp/go/ruby 的查询已**编译校验通过**（对 CodeQL 官方库类型检查无误），建议首次用你的真实 DB 复核一次——若某语言查询对不上，控制台会显示明确降级原因（不会崩）。

**对交付 DB 的约束**
1. **从与被审项目相同的源码树构建**（查询结果的相对路径要能对上工作区同名文件）。
2. **finalize 完成的完整库**（`database create` 会自动 finalize；系统另有完整性校验）。
3. 语言必须在上面的支持列表内。

---

## B. JSONL（语言无关兜底，如 PHP）

给一个**目录**（内含 `edges.jsonl` + 可选 `dataflow.jsonl`），或直接给 `edges.jsonl` 文件（系统会在同目录自动找 `dataflow.jsonl`）。

### B.1 `edges.jsonl` —— 调用图（必需）
每行一条调用边：

| 字段 | 类型 | 必填 | 含义 |
|---|---|---|---|
| `caller_file` / `callee_file` | string | 是 | 端点函数所在文件，**项目相对路径、正斜杠** |
| `caller_line` / `callee_line` | int | 是 | 端点函数的**定义行**（1 起） |
| `caller_func` / `callee_func` | string | 是 | 函数名（**简单名**，与 Tree-sitter 抽取一致，非限定名） |
| `call_site_line` | int | 否 | 调用发生处行号（缺省 -1） |

```jsonl
{"caller_file":"application/index/controller/Vod.php","caller_line":40,"caller_func":"detail","callee_file":"application/common/model/Vod.php","callee_line":88,"callee_func":"getInfo","call_site_line":52}
```

### B.2 `dataflow.jsonl` —— 逐点污点（可选，让 `cg_dataflow` 在 JSONL 模式也可用）
你离线用 CodeQL/Joern/任意工具跑污点分析，把找到的 **source→sink 流**导出，每行一条：

| 字段 | 类型 | 必填 | 含义 |
|---|---|---|---|
| `source_file` / `sink_file` | string | 是 | 源/汇所在文件（项目相对路径、正斜杠） |
| `source_line` / `sink_line` | int | 是 | 源/汇所在行 |
| `path` | array | 否 | 中间跳（展示用），如 `["a.php:31","b.php:53"]` |
| `note` | string | 否 | 备注（如 CWE） |

```jsonl
{"source_file":"a.php","source_line":31,"sink_file":"b.php","sink_line":53,"path":["a.php:31","b.php:53"],"note":"CWE-78"}
```
系统在 `cg_dataflow(src,sink)` 时**查这张表**（端点按路径后缀 + 行号 ±2 匹配）：命中→有污点流+路径；未命中→`none_found`（与 CodeQL 对该对的回答一致，非漏答）。**是静态快照**：只含你离线那次找到的流。

### B.3 硬约束（决定边/流能否被采纳）
系统把每个端点 `(file, name/line)` 映射到 **Tree-sitter 解析出的函数**，对不上就丢：
1. `*_file` 项目相对路径 + 正斜杠；
2. `*_func` 用**源码简单函数名**（非 `Class.method` 限定名）；
3. `*_line` 用函数定义行（1 起，容差 ±偏差）；
4. 端点函数须真实存在于源码。
> 自检：若解析出边但一条都对不齐，控制台顶部提示 `手动…产出 N 条边，但没有一条能对齐源码函数…`，并回落 Tree-sitter；成功时【调用图状态】= `CodeQL（人工离线构建）`、不报降级。

---

## C. 覆盖范围与落地位置

- **调用图类工具**（两种模式都全覆盖）：`cg_overview / cg_callers / cg_callees / cg_reachable / cg_path / cg_subgraph`、`check_reachability`。
- **`cg_dataflow`（逐点污点）**：CodeQL DB 模式→现算；JSONL 模式→查 `dataflow.jsonl`；JSONL 无 dataflow.jsonl 时明确说明“改用 cg_reachable + read_file”。
- **实现**：前端 `History.tsx`（开关 + 路径 → `config.callgraph_manual(_path)`）；后端 `orchestrator.run_audit` 审计前 `callgraph.set_manual(root,path)`、结束 `clear_manual`；`callgraph._resolve_manual` 按“文件/DB 目录”自动分流；引擎标签 `codeql-manual`（排名最高、不报降级）。
