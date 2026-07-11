# 评测报告

## 1. 运行摘要
- run_id: `run-20260711-013945-veriaudit-gaochengxuan`
- 成员: gaochengxuan
- 项目/工具: VeriAudit (git:6e75391-dirty)
- 靶场目标: 基线测试 (D:/my_allkinds_document/aaDa3_xia/BenchmarkPython/BenchmarkPython)
- 运行状态: success
- 总耗时: 4538.3 秒
- 最终上报漏洞数(去重): 53（其中已验证 48，疑似待复核 5）
- 已上报结果中的误报(对照基准答案): 0
- 验证阶段内部剪除的候选（不计入上报结果，也不算系统误报）: 7
- 失败项: 0

## 2. 环境与配置
- 模型: deepseek/deepseek-v4-flash
- 温度: None（系统未显式设置，使用 provider 默认值）
- 预算: 最大运行 None 秒；自适应预算见 env.snapshot.json
- 工具版本: git:6e75391-dirty
- 靶场快照: git=a4567ea5977c
- 沙箱: 启用

## 3. 执行方法
- 启动命令: `uvicorn app.main:app`（读取 backend/.env），前端 `vite` 实时监视
- 审计深度: deep
- 扫描范围: D:/my_allkinds_document/aaDa3_xia/BenchmarkPython/BenchmarkPython
- 验证方式: 静态数据流(CodeQL/Joern) + Docker 沙箱动态复现

## 4. 漏洞列表（系统最终上报 53 条；验证阶段内部剪除的候选见 raw/rejected_candidates.jsonl）
| finding_id | 标题 | 严重度 | CWE | 文件:行 | 状态 | GT | 证据 |
|---|---|---|---|---|---|---|---|
| finding-0001 | OS Command Injection — testcode/Benchmar | critical | CWE-78 | testcode/BenchmarkTest00165.py:57 | verified | tp | 2 |
| finding-0002 | OS Command Injection — testcode/Benchmar | critical | CWE-78 | testcode/BenchmarkTest00166.py:53 | verified | tp | 2 |
| finding-0003 | OS Command Injection — testcode/Benchmar | critical | CWE-78 | testcode/BenchmarkTest00167.py:53 | verified | tp | 2 |
| finding-0004 | OS Command Injection — testcode/Benchmar | critical | CWE-78 | testcode/BenchmarkTest00168.py:60 | verified | tp | 2 |
| finding-0005 | OS Command Injection — testcode/Benchmar | critical | CWE-78 | testcode/BenchmarkTest00267.py:55 | verified | tp | 2 |
| finding-0006 | OS Command Injection — testcode/Benchmar | critical | CWE-78 | testcode/BenchmarkTest00268.py:55 | verified | tp | 2 |
| finding-0007 | OS Command Injection — testcode/Benchmar | critical | CWE-78 | testcode/BenchmarkTest00431.py:51 | verified | tp | 2 |
| finding-0008 | OS Command Injection — testcode/Benchmar | critical | CWE-78 | testcode/BenchmarkTest00432.py:53 | verified | tp | 2 |
| finding-0009 | Code Injection / Unsafe Eval — testcode/ | critical | CWE-94 | testcode/BenchmarkTest00074.py:51 | verified | tp | 2 |
| finding-0010 | Code Injection / Unsafe Eval — testcode/ | critical | CWE-94 | testcode/BenchmarkTest00159.py:45 | verified | tp | 2 |
| finding-0011 | Code Injection / Unsafe Eval — testcode/ | critical | CWE-94 | testcode/BenchmarkTest00160.py:49 | verified | tp | 2 |
| finding-0012 | Code Injection / Unsafe Eval — testcode/ | critical | CWE-94 | testcode/BenchmarkTest00161.py:40 | verified | tp | 2 |
| finding-0013 | Code Injection / Unsafe Eval — testcode/ | critical | CWE-94 | testcode/BenchmarkTest00342.py:49 | verified | tp | 2 |
| finding-0014 | Code Injection / Unsafe Eval — testcode/ | critical | CWE-94 | testcode/BenchmarkTest00343.py:45 | verified | tp | 2 |
| finding-0015 | Code Injection / Unsafe Eval — testcode/ | critical | CWE-94 | testcode/BenchmarkTest00422.py:44 | verified | tp | 2 |
| finding-0016 | Code Injection / Unsafe Eval — testcode/ | critical | CWE-94 | testcode/BenchmarkTest00425.py:43 | verified | tp | 2 |
| finding-0017 | Insecure Deserialization — testcode/Benc | critical | CWE-502 | testcode/BenchmarkTest00078.py:53 | verified | tp | 2 |
| finding-0018 | Insecure Deserialization — testcode/Benc | critical | CWE-502 | testcode/BenchmarkTest00164.py:47 | verified | tp | 2 |
| finding-0019 | Insecure Deserialization — testcode/Benc | critical | CWE-502 | testcode/BenchmarkTest00269.py:47 | verified | tp | 2 |
| finding-0020 | Insecure Deserialization — testcode/Benc | critical | CWE-502 | testcode/BenchmarkTest00270.py:48 | verified | tp | 2 |
| finding-0021 | Insecure Deserialization — testcode/Benc | critical | CWE-502 | testcode/BenchmarkTest00433.py:47 | verified | tp | 2 |
| finding-0022 | Insecure Deserialization — testcode/Benc | critical | CWE-502 | testcode/BenchmarkTest00507.py:55 | verified | tp | 2 |
| finding-0023 | OS Command Injection — testcode/Benchmar | critical | CWE-78 | testcode/BenchmarkTest00511.py:57 | verified | tp | 2 |
| finding-0024 | OS Command Injection — testcode/Benchmar | critical | CWE-78 | testcode/BenchmarkTest00606.py:51 | verified | tp | 2 |
| finding-0025 | Insecure Deserialization — testcode/Benc | critical | CWE-502 | testcode/BenchmarkTest00510.py:46 | verified | tp | 2 |
| finding-0026 | Insecure Deserialization — testcode/Benc | critical | CWE-502 | testcode/BenchmarkTest00605.py:47 | verified | tp | 2 |
| finding-0027 | Insecure Deserialization — testcode/Benc | critical | CWE-502 | testcode/BenchmarkTest00657.py:53 | candidate | tp | 1 |
| finding-0028 | Insecure Deserialization — testcode/Benc | critical | CWE-502 | testcode/BenchmarkTest00734.py:46 | verified | tp | 2 |
| finding-0029 | Insecure Deserialization — testcode/Benc | critical | CWE-502 | testcode/BenchmarkTest00735.py:46 | verified | tp | 2 |
| finding-0030 | Insecure Deserialization — testcode/Benc | critical | CWE-502 | testcode/BenchmarkTest00825.py:47 | verified | tp | 2 |
| finding-0031 | Insecure Deserialization — testcode/Benc | critical | CWE-502 | testcode/BenchmarkTest00898.py:49 | verified | tp | 2 |
| finding-0032 | OS Command Injection — testcode/Benchmar | critical | CWE-78 | testcode/BenchmarkTest00899.py:64 | verified | tp | 2 |
| finding-0033 | OS Command Injection — testcode/Benchmar | critical | CWE-78 | testcode/BenchmarkTest01191.py:52 | verified | tp | 2 |
| finding-0034 | Path Traversal — testcode/BenchmarkTest0 | medium | CWE-22 | testcode/BenchmarkTest00001.py:47 | verified | tp | 2 |
| finding-0035 | Path Traversal — testcode/BenchmarkTest0 | medium | CWE-22 | testcode/BenchmarkTest00002.py:49 | verified | tp | 2 |
| finding-0036 | Path Traversal — testcode/BenchmarkTest0 | medium | CWE-22 | testcode/BenchmarkTest00003.py:50 | verified | tp | 2 |
| finding-0037 | Path Traversal — testcode/BenchmarkTest0 | medium | CWE-22 | testcode/BenchmarkTest00008.py:51 | verified | tp | 2 |
| finding-0038 | SQL Injection — testcode/BenchmarkTest00 | high | CWE-89 | testcode/BenchmarkTest00099.py:46 | verified | tp | 2 |
| finding-0039 | SQL Injection — testcode/BenchmarkTest00 | high | CWE-89 | testcode/BenchmarkTest00283.py:46 | verified | tp | 2 |
| finding-0040 | SQL Injection — testcode/BenchmarkTest00 | high | CWE-89 | testcode/BenchmarkTest00284.py:44 | verified | tp | 2 |
| finding-0041 | SQL Injection — testcode/BenchmarkTest00 | critical | CWE-89 | testcode/BenchmarkTest00454.py:41 | verified | tp | 2 |
| finding-0042 | CWE-90 LDAP Injection — testcode/Benchma | high | CWE-90 | testcode/BenchmarkTest00265.py:42 | verified | tp | 2 |
| finding-0043 | CWE-90 LDAP Injection — testcode/Benchma | medium | CWE-90 | testcode/BenchmarkTest00266.py:55 | verified | tp | 2 |
| finding-0044 | CWE-90 LDAP Injection — testcode/Benchma | medium | CWE-90 | testcode/BenchmarkTest00427.py:49 | verified | tp | 1 |
| finding-0045 | CWE-90 LDAP Injection — testcode/Benchma | high | CWE-90 | testcode/BenchmarkTest00429.py:49 | candidate | tp | 0 |
| finding-0046 | CWE-90 LDAP Injection — testcode/Benchma | high | CWE-90 | testcode/BenchmarkTest00430.py:48 | candidate | tp | 0 |
| finding-0047 | CWE-90 LDAP Injection — testcode/Benchma | medium | CWE-90 | testcode/BenchmarkTest00505.py:50 | verified | tp | 2 |
| finding-0048 | Path Traversal — testcode/BenchmarkTest0 | high | CWE-643 | testcode/BenchmarkTest00018.py:49 | candidate | tp | 1 |
| finding-0049 | Path Traversal — testcode/BenchmarkTest0 | high | CWE-643 | testcode/BenchmarkTest00019.py:53 | candidate | tp | 1 |
| finding-0050 | Path Traversal — testcode/BenchmarkTest0 | high | CWE-643 | testcode/BenchmarkTest00101.py:54 | verified | tp | 1 |
| finding-0051 | Path Traversal — testcode/BenchmarkTest0 | medium | CWE-643 | testcode/BenchmarkTest00103.py:48 | verified | tp | 2 |
| finding-0052 | Path Traversal — testcode/BenchmarkTest0 | high | CWE-643 | testcode/BenchmarkTest00104.py:50 | verified | tp | 1 |
| finding-0053 | Path Traversal — testcode/BenchmarkTest0 | medium | CWE-643 | testcode/BenchmarkTest00107.py:56 | verified | tp | 1 |

## 5. PoC 与验证结果
- 已生成 PoC: 51
- 已执行 PoC: 53
- 沙箱验证成功: 44
- 失败/未复现: 9
- 被策略阻断: 0

## 6. 证据链
- 原始报告: `raw/veriaudit-report.md` / `.json` / `.sarif`
- 每条 finding 的 PoC/沙箱日志/HTTP 交换见 `artifacts/finding-XXXX/`
- 模型调用摘要: `model_calls.jsonl`（含实测 token）；审计轨迹: `analysis_trace.jsonl`

## 7. 误报、不确定项与限制
- 已上报结果中的误报: 0 条（对照 OWASP 基准答案，上报的 53 条全部命中真实漏洞）
- 验证阶段内部剪除候选: 7 条 —— 这是系统在产出前的自我纠错，不属于最终结果、也不计为系统误报（明细见 raw/rejected_candidates.jsonl）
- 疑似待复核(candidate): 5 条
- 项目不支持: 每次调用成本(缺 deepseek-v4-flash 官方单价，留空避免编造)；prompt/response 全文（仅存 hash）
- 环境限制: temperature 未由系统显式设置为 0

## 8. 修复建议
- **finding-0001** CWE-78: 1. Never concatenate user input directly into shell commands. Use subprocess.run() with a list of arguments (no shell=True) to avoid shell interpretation.
2. If shell execution is 
- **finding-0002** CWE-78: Never pass user-supplied input directly to shell commands. Use `subprocess.run()` with a list of arguments (no `shell=True`) instead of a string: e.g., `subprocess.run(["sh", "-c",
- **finding-0003** CWE-78: Never concatenate user input directly into shell commands. Use subprocess.run() with a list of arguments (no shell=True) instead of a string. Alternatively, if shell=True is requir
- **finding-0004** CWE-78: 1. Never concatenate user input into shell command strings. Use subprocess.run() with a list of arguments (e.g., subprocess.run(['echo', bar], capture_output=True)) instead of shel
- **finding-0005** CWE-78: 永远不要将用户输入直接拼接进 shell 命令。应使用无需 shell 解释的调用方式，例如 subprocess.run(['echo', bar]) 而非 subprocess.run(['sh', '-c', f'echo {bar}'])。如需支持复杂命令，应使用 shlex.quote() 对用户输入进行转义，或使用白名单验证输入仅允许安全字符。
- **finding-0006** CWE-78: Never pass user input directly into a shell command. Replace the shell-based approach with a safe API:
1. Use `subprocess.run(['echo', bar], ...)` without `shell=True` or `sh -c` —
- **finding-0007** CWE-78: 1. 使用 subprocess.run() 时传参数列表而非字符串，禁用 shell=True：
   subprocess.run(["echo", bar], capture_output=True, encoding="utf-8")
2. 如果必须使用 shell=True，则使用 shlex.quote() 对用户输入进行转义：
   impor
- **finding-0008** CWE-78: 1. 永远不要将用户输入拼接进shell命令。使用subprocess.run()时传入参数列表而非字符串，并设置shell=False。如：subprocess.run(['echo', bar], capture_output=True)。2. 如果必须使用shell=True，则用shlex.quote()对用户输入进行转义。3. 更安全的方案：避免依
- **finding-0009** CWE-94: 1. 绝对不要将用户可控输入传递给 exec()、eval() 等动态代码执行函数。
2. 如果必须执行用户提供的代码，使用安全沙箱（如受限子进程、Docker 容器）隔离执行环境。
3. 改用安全的替代方案：如通过映射表、策略模式或 eval 的安全替代库（如 PyPy sandbox）。
4. 实施输入验证：严格校验输入内容仅允许预期的安全字符集。
5.
- **finding-0010** CWE-94: 1. **绝对禁止将用户输入传入 exec()/eval()/compile()**。这些函数执行任意 Python 代码，本质上是 RCE。
2. 如果需求是执行用户提交的表达式，应使用安全的沙箱（如 AST 解析后的白名单求值），但强烈建议重新设计业务逻辑。
3. 更安全的替代方案：预定义可执行操作列表，用户只能选择索引/名称。
4. 添加输入白名单校验
- **finding-0011** CWE-94: 1. **绝对不要将用户输入传入 `exec()`**。`exec()` 执行任意 Python 代码，没有任何安全使用方式。
2. 如果本测试用例意在模拟某种动态代码执行，应用白名单模式：预定义一组允许执行的表达式/函数名，用户仅能通过索引/枚举选择。
3. 考虑使用 `ast.literal_eval()` 替代 `exec()` 处理简单数据类型（字符
- **finding-0012** CWE-94: 绝对不要将用户输入直接或间接传入 `exec()`、`eval()`、`compile()` 等动态代码执行函数。修复方案：
1. 彻底移除 `exec()` 调用，改用安全的替代逻辑；
2. 如果必须动态执行，应使用白名单验证——仅允许预定义的有限指令集；
3. 不可能通过输入净化来安全地使用 `exec()`——任何用户可控数据进入 `exec()` 都
- **finding-0013** CWE-94: 永远不要将用户输入直接或间接传递给 eval()。正确的修复方案：
1. 完全移除 eval 调用，使用安全的替代逻辑。
2. 如果必须动态求值，使用白名单机制只允许预定义的表达式/函数。
3. 对任何用户输入进行严格的输入验证和净化（白名单模式）。
4. OWASP Benchmark 是测试用例，生产代码中不应出现 eval() 与用户输入的组合。
- **finding-0014** CWE-94: 绝对不要将用户可控输入直接或间接传递给 eval()。改用安全替代方案：如需要动态计算数值用 int()/float() 转换；需要动态执行函数用映射表（dict）查找；需要动态评估表达式使用受限沙箱（如 ast.literal_eval()）。在本例中，若需对用户输入做某种处理，应使用预先定义的白名单操作集合。
- **finding-0015** CWE-94: 永远不要将用户可控的输入传入 eval()/exec() 等动态执行函数。应重构代码逻辑，使用安全替代方案（如字典映射、预定义操作类）。若必须动态计算表达式，应使用白名单机制严格限定可执行的表达式范围，并对输入做严格的语法/语义过滤。
- **finding-0016** CWE-94: 绝对不要将用户可控输入传入 exec() / eval()。对于 OWASP Benchmark 测试用例，此漏洞为预设的 benchmark 样本，不适用于实际修复。但在真实生产环境中应：1) 永远不要使用 exec/eval 处理用户输入；2) 如需动态代码执行，使用安全的沙箱机制（如 subprocess 配合白名单）；3) 对用户输入做严格的类型/格
- **finding-0017** CWE-502: Never use pickle.loads() on untrusted data. Use a safe serialization format like JSON instead. If deserialization of complex objects is required, use a safe alternative that only a
- **finding-0018** CWE-502: 绝对不要使用 `pickle.loads()` 处理不受信任的用户输入。pickle 反序列化会执行任意代码，是公认的不安全设计。修复方案：1) 改用安全的序列化格式如 JSON（`json.loads()`）；2) 如需传递复杂对象，使用消息队列或白名单签名验证机制；3) 如果必须反序列化，对输入实施强签名验证（HMAC），确保只有受信来源的数据被处理。
- **finding-0019** CWE-502: 将 `yaml.load(bar, Loader=yaml.Loader)` 替换为 `yaml.safe_load(bar)`。`yaml.Loader` 完全信任输入并可反序列化任意 Python 对象，`yaml.SafeLoader` 仅支持标准 YAML 标量/序列/映射，无法实例化任意类。如果确实需要复杂 YAML 功能，应使用 `yaml.Sa
- **finding-0020** CWE-502: 1. Replace yaml.load() with yaml.safe_load() which only deserializes safe Python types (dict, list, str, int, float, bool, None). yaml.Loader (the default/unsafe loader) must never
- **finding-0021** CWE-502: Replace `yaml.load(bar, Loader=yaml.Loader)` with `yaml.safe_load(bar)` on line 46 of testcode/BenchmarkTest00433.py. The `yaml.Loader` (full loader) deserializes arbitrary Python 
- **finding-0022** CWE-502: Never use pickle.loads() on untrusted data. Pickle deserialization is inherently unsafe - it can execute arbitrary code during unpickling. Remediations:
1. Use a safe serialization
- **finding-0023** CWE-78: 1. 永远不要将用户可控输入直接拼接到 shell 命令中。对于 echo 操作，应使用 Python 原生方式（如直接 print），而非通过 shell 子进程。
2. 如果必须使用 subprocess 执行命令，应使用参数列表形式（不经过 shell 解释），例如 subprocess.run(["echo", bar])，这样 bar 仅作为字面参
- **finding-0024** CWE-78: 1. 【首选·彻底修复】禁止直接拼接用户输入到shell命令。将用户的bar参数通过subprocess.run的参数列表传递（不使用shell=True），或将echo命令完全替换为Python内置的print/日志功能。  
2. 【输入净化】若必须使用shell=True，对bar进行严格转义：使用shlex.quote(bar)阻止shell元字符解
- **finding-0025** CWE-502: 1. **永远不要对不可信数据使用pickle.loads()**。pickle设计上就是不安全的，即使加了签名验证也无法防御pickle本身的功能滥用。
2. 改用安全的序列化格式替代pickle，如：JSON (json.loads)、YAML（使用安全解析器如yaml.safe_load）、MessagePack等。
3. 若必须使用pickle，应采
- **finding-0026** CWE-502: 1. 永远不要使用 pickle.loads() 处理不可信数据。pickle 设计上就不安全，反序列化时执行任意代码。2. 改用安全序列化格式如 JSON（json.loads）并通过 schema 验证。3. 如需使用 pickle，必须在反序列化前进行 HMAC 签名验证，确保数据来自可信源。4. 删除或移除当前对 unsafe_b64decode+p
- **finding-0027** CWE-502: 不要反序列化不可信数据。使用安全格式（JSON），或 yaml.safe_load；如必须，做签名校验与类型白名单。
- **finding-0028** CWE-502: 1. Never use pickle.loads() on untrusted data. Python pickle is fundamentally insecure against deserialization attacks.
2. Use a safe serialization format like JSON (json.loads) in
- **finding-0029** CWE-502: Never deserialize untrusted data with pickle.loads(). Replace pickle with a safe serialization format such as JSON (json.loads/json.dumps). If deserialization of complex objects is
- **finding-0030** CWE-502: 永远不要对不可信数据使用 pickle.loads()。pickle 反序列化会执行任意代码，不是安全的数据交换格式。替代方案：(1) 使用 JSON 或其它安全序列化格式（如 msgpack, protobuf）；(2) 如果必须使用 pickle，应在隔离的沙箱环境中反序列化，或对输入做严格的数字签名验证（确保只有可信方签名过的数据才被反序列化）。
- **finding-0031** CWE-502: 永远不要使用 pickle.loads() 反序列化不可信数据。Python pickle 不是安全格式，会执行任意代码。替代方案：(1) 使用 JSON（json.loads）或其他安全序列化格式；(2) 如必须反序列化 Python 对象，使用 hmac 签名验证数据完整性；(3) 或使用更安全的序列化库如 marshmallow 配合 schema 校
- **finding-0032** CWE-78: 禁止将用户输入直接拼接到 shell 命令字符串中。应使用安全方案之一：1) 若只需 echo 用户输入，改用 Python 原生 print() 或直接返回输入，完全避免 shell 调用；2) 如需调用外部命令，使用 subprocess.run() 的列表形式（不传 shell=True/-c），将用户输入作为参数传递而非命令字符串拼接；3) 对必须经
- **finding-0033** CWE-78: NEVER use user input in shell commands passed to `subprocess.run()` with `shell=True` or via `sh -c`. Use safe alternatives: (1) Use `subprocess.run()` with a list of arguments (e.
- **finding-0034** CWE-22: 1. Validate and sanitize user input before using it in file path operations. Reject inputs containing path traversal sequences like '../' or '..\\'.
2. Use os.path.abspath() or os.
- **finding-0035** CWE-22: 1. 对用户输入的文件路径进行白名单校验，仅允许预期的文件名/前缀
2. 使用 os.path.abspath() 将用户输入拼接后的路径解析为绝对路径，并验证其是否在允许的基准目录内（如 os.path.commonpath）
3. 移除或替换路径中的'..'序列
4. 使用安全的文件访问 API，如将用户输入映射为预定义的资源标识符而非直接拼接路径
- **finding-0036** CWE-22: 对用户控制的文件路径参数应进行路径规范化与合法性校验：1) 使用 os.path.abspath() 规范化后检查是否在允许的基准目录内；2) 移除或拒绝包含 '../' 或 '..\\' 的输入；3) 使用白名单机制限制可访问的文件名；4) 考虑使用 UUID 或哈希值映射真实文件路径，避免直接暴露文件系统结构。
- **finding-0037** CWE-22: 1. Validate and sanitize file path components: reject any input containing '../' or absolute path indicators. 2. Use path canonicalization (e.g., pathlib.Path.resolve()) and verify
- **finding-0038** CWE-89: Replace f-string interpolation with parameterized queries. For SQLite, use '?' placeholders:
  sql = 'SELECT username from USERS where password = ?'
  cur.execute(sql, (bar,))
This
- **finding-0039** CWE-89: 使用参数化查询（预编译语句）替代 f-string 拼接。例如：cur.execute('SELECT username from USERS where password = ?', (bar,))。对于 SQLite 使用 ? 占位符，对于其他数据库使用对应参数占位符。
- **finding-0040** CWE-89: Replace the f-string SQL construction with parameterized queries. In SQLite/Python, use `?` placeholders:

```python
sql = 'SELECT username from USERS where password = ?'
cur.execu
- **finding-0041** CWE-89: 使用参数化查询（prepared statement）替代 f-string 插值。对于 SQLite，应将第 41-44 行改为：
```
sql = 'SELECT username from USERS where password = ?'
cur.execute(sql, (bar,))
```
这可以完全避免 SQL 注入风险，因为用户输入被视为
- **finding-0042** CWE-90: 使用 ldap3 内置的过滤器转义函数对用户输入进行净化，或使用参数化查询（若 ldap3 支持）。具体方案：
1. `from ldap3.utils.conv import escape_filter_chars`
2. `safe_bar = escape_filter_chars(bar)`
3. `filter = f'(&(objectclass
- **finding-0043** CWE-90: Sanitize/escape LDAP search filter inputs before constructing filter strings. Use ldap3's built-in filter escaping: `from ldap3.utils.conv import escape_filter_chars` then `safe_ba
- **finding-0044** CWE-90: 1. 使用 ldap3 提供的转义函数对用户输入进行过滤器转义：`from ldap3.utils.conv import escape_filter_chars`，然后 `safe_bar = escape_filter_chars(bar)` 再拼接。2. 或改用参数化 LDAP 查询（如 ldap3 的 filter 参数支持过滤器模板）。3. 避免将
- **finding-0047** CWE-90: 使用 ldap3.utils.dn.escape_rdn() 或自定义函数对用户输入进行 LDAP 过滤器转义。对于过滤器中的特殊字符（*、(、)、\、NUL 等），应当进行转义处理。推荐使用 ldap3 库提供的 escape_filter_chars（如适用）或手动替换：str.replace('*', '\\2a').replace('(', '\\2
- **finding-0048** CWE-643: 对文件路径做规范化并限制在受信根目录内（resolve 后校验前缀）；拒绝 `..`/绝对路径；用白名单映射代替直接拼接。
- **finding-0049** CWE-643: 对文件路径做规范化并限制在受信根目录内（resolve 后校验前缀）；拒绝 `..`/绝对路径；用白名单映射代替直接拼接。
- **finding-0050** CWE-643: 1. **Use parameterized XPath (preferred):** Use `elementpath.select(root, '/Employees/Employee[@emplid=$var]', {'var': bar})` with variable bindings instead of string interpolation
- **finding-0051** CWE-643: 1. 使用参数化 XPath 查询（预编译表达式 + 变量绑定）：lxml.etree.XPath 支持变量绑定，如 root.xpath('/Employees/Employee[@emplid=$eid]', eid=bar)。2. 对用户输入进行严格净化：移除单引号 '、双引号 "、方括号 []、斜杠 / 等 XPath 特殊字符。3. 使用输入白名单
- **finding-0052** CWE-643: 1. 修复第58行的 f-string 语法错误（使用变量暂存或改用双引号包裹外层字符串）：`f\"Your XPATH query results are: <br>[ {', '.join(node_strings)} ]\"` 或 `', '.join(node_strings)` 预先赋值给变量
2. 使用参数化 XPath 查询（lxml.etre
- **finding-0053** CWE-643: 1. 修复第62行语法错误：将 f-string 的界定符改为双引号、或转义内嵌单引号；2. 使用参数化 XPath 查询（如 lxml 不支持原生参数化，可使用 XPath 变量绑定或预编译表达式前对输入做白名单校验）；3. 对用户输入进行严格净化，只允许预期的合法字符（如仅数字/字母），或使用专门的 XPath 注入防护库。

## 9. 指标摘要
- 最终上报(去重): 53；已验证: 48；上报误报: 0；内部剪除候选: 7
- Ground Truth: precision=1.0 recall=0.1173 f1=0.2099 (TP=53 FP=0 FN=399 / 正样本 452)
- LLM 调用: 862；总 token: 11336623；成本: None
- 覆盖: 分析文件 104 / 发现 1239；语言 ['javascript', 'python']
