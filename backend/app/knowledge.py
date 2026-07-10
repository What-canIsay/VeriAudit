"""Vulnerability knowledge base + language adapters.

This is the domain knowledge that powers both the deterministic detector
(candidate generation, taint sinks/sources, sanitizers) and the LLM agents'
kb_search tool (remediation, PoC hints). Multi-language by design — extend by
adding language keys / adapters (see docs/01 §6, docs/04).
"""
from __future__ import annotations

from typing import Dict, List, Optional

# ----------------------------------------------------------------------------
# Language adapters
# ----------------------------------------------------------------------------
LANGUAGE_ADAPTERS: Dict[str, dict] = {
    "python": {
        "exts": [".py"],
        "entrypoints": [
            r"@app\.route", r"@router\.(get|post|put|delete|patch)", r"@blueprint\.route",
            r"def\s+\w+\(.*request", r"application\s*=\s*", r"if\s+__name__\s*==",
        ],
        "manifest": ["requirements.txt", "pyproject.toml", "Pipfile"],
        "sandbox": {"base": "python:3.11-slim", "install": "pip install -r requirements.txt || true",
                     "run": "python app.py"},
    },
    "javascript": {
        "exts": [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
        "entrypoints": [
            r"app\.(get|post|put|delete|use)", r"router\.(get|post|put|delete)",
            r"http\.createServer", r"addEventListener\(",
        ],
        "manifest": ["package.json"],
        "sandbox": {"base": "node:20-slim", "install": "npm install --omit=dev || true",
                     "run": "node index.js"},
    },
    "php": {
        "exts": [".php"],
        "entrypoints": [r"\$_(GET|POST|REQUEST|COOKIE|SERVER)", r"->(get|post)\("],
        "manifest": ["composer.json"],
        "sandbox": {"base": "php:8.2-cli", "install": "true", "run": "php -S 0.0.0.0:8000"},
    },
    "java": {
        "exts": [".java"],
        "entrypoints": [r"@(Get|Post|Put|Delete|Request)Mapping", r"HttpServletRequest"],
        "manifest": ["pom.xml", "build.gradle"],
        "sandbox": {"base": "eclipse-temurin:17-jdk", "install": "true", "run": "true"},
    },
    "go": {
        "exts": [".go"],
        "entrypoints": [r"http\.HandleFunc", r"\.(GET|POST|PUT|DELETE)\(", r"gin\.", r"mux\."],
        "manifest": ["go.mod"],
        "sandbox": {"base": "golang:1.22", "install": "go mod download || true", "run": "go run ."},
    },
}

EXT_TO_LANG: Dict[str, str] = {}
for _lang, _a in LANGUAGE_ADAPTERS.items():
    for _e in _a["exts"]:
        EXT_TO_LANG[_e] = _lang

# Untrusted input markers (taint sources) per language.
SOURCES: Dict[str, List[str]] = {
    "python": [r"request\.(args|form|values|json|data|cookies|headers|files)",
               r"\bos\.environ\b", r"\bsys\.argv\b", r"\binput\s*\(", r"flask\.request"],
    "javascript": [r"req\.(query|body|params|headers|cookies)", r"process\.argv",
                   r"location\.(search|hash|href)", r"window\.name"],
    "php": [r"\$_(GET|POST|REQUEST|COOKIE)\b", r"\$_SERVER\[", r"php://input"],
    "java": [r"getParameter\s*\(", r"getHeader\s*\(", r"getQueryString\s*\("],
    "go": [r"r\.URL\.Query\(\)", r"r\.FormValue\(", r"r\.PostFormValue\("],
}

# ----------------------------------------------------------------------------
# Vulnerability rules — sinks / sanitizers / metadata per CWE class.
# ----------------------------------------------------------------------------
VULN_RULES: List[dict] = [
    {
        "id": "command-injection", "cwe": "CWE-78", "name": "OS Command Injection",
        "severity": "critical", "reproducible": True,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "sinks": {
            "python": [r"os\.system\s*\(", r"subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True", r"os\.popen\s*\("],
            "javascript": [r"child_process\.(exec|execSync)\s*\(", r"\.exec\s*\("],
            "php": [r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(", r"`.*\$"],
            "java": [r"Runtime\.getRuntime\(\)\.exec\s*\(", r"ProcessBuilder\s*\("],
            "go": [r"exec\.Command\s*\(", r"exec\.CommandContext\s*\("],
        },
        "sanitizers": {"python": [r"shlex\.quote"], "php": [r"escapeshellarg", r"escapeshellcmd"]},
        "poc_hint": "Inject `; id` or `$(id)` into the tainted parameter; success oracle: response/log contains `uid=`.",
        "remediation": "避免将用户输入拼接进 shell 命令。使用不经 shell 的参数化调用（如 Python 的 subprocess.run([...], shell=False)），必要时用 shlex.quote 转义；对允许的取值做白名单校验。",
    },
    {
        "id": "sql-injection", "cwe": "CWE-89", "name": "SQL Injection",
        "severity": "high", "reproducible": True,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "sinks": {
            "python": [r"\.execute\s*\(\s*[f\"']", r"\.execute\s*\([^)]*%\s*", r"\.execute\s*\([^)]*\+", r"\.raw\s*\("],
            "javascript": [r"\.query\s*\(\s*[`\"'][^`\"']*\$\{", r"\.query\s*\([^)]*\+"],
            "php": [r"mysqli?_query\s*\([^)]*\$", r"->query\s*\([^)]*\$", r"\bquery\s*\(\s*[\"'].*\$"],
            "java": [r"createStatement\(\)", r"Statement.*executeQuery\s*\([^)]*\+"],
            "go": [r"db\.(Query|Exec)\s*\(\s*[\"`][^\"`]*\+", r"fmt\.Sprintf\s*\([^)]*(SELECT|INSERT|UPDATE|DELETE)"],
        },
        "sanitizers": {"python": [r"execute\s*\([^)]*,\s*[\(\[]"], "javascript": [r"\.query\([^)]*,\s*\["]},
        "poc_hint": "Inject `' OR '1'='1` / boolean payloads; oracle: differing responses between true/false payloads or DB error leakage.",
        "remediation": "使用参数化查询/预编译语句（占位符 + 参数数组），绝不用字符串拼接构造 SQL；ORM 层避免 raw SQL 拼接。",
    },
    {
        "id": "code-injection", "cwe": "CWE-94", "name": "Code Injection / Unsafe Eval",
        "severity": "critical", "reproducible": True,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "sinks": {
            "python": [r"\beval\s*\(", r"\bexec\s*\(", r"\bcompile\s*\("],
            "javascript": [r"\beval\s*\(", r"new\s+Function\s*\(", r"setTimeout\s*\(\s*[\"'`]"],
            "php": [r"\beval\s*\(", r"assert\s*\(", r"create_function\s*\("],
        },
        "sanitizers": {},
        "poc_hint": "Inject an expression with an observable side effect; oracle: expression evaluated (e.g. arithmetic result or marker output).",
        "remediation": "禁止对用户输入使用 eval/exec/Function 等动态执行；改用安全的解析/白名单分发，或 ast.literal_eval 等受限求值。",
    },
    {
        "id": "deserialization", "cwe": "CWE-502", "name": "Insecure Deserialization",
        "severity": "critical", "reproducible": True,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "sinks": {
            "python": [r"pickle\.loads?\s*\(", r"yaml\.load\s*\((?![^)]*Loader)", r"marshal\.loads?\s*\("],
            "php": [r"\bunserialize\s*\("],
            "java": [r"ObjectInputStream", r"readObject\s*\("],
        },
        "sanitizers": {"python": [r"yaml\.safe_load"]},
        "poc_hint": "Provide a crafted serialized payload; oracle: gadget side-effect (marker file/command).",
        "remediation": "不要反序列化不可信数据。使用安全格式（JSON），或 yaml.safe_load；如必须，做签名校验与类型白名单。",
    },
    {
        "id": "path-traversal", "cwe": "CWE-22", "name": "Path Traversal",
        "severity": "high", "reproducible": True,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "sinks": {
            "python": [r"\bopen\s*\(", r"send_file\s*\(", r"os\.path\.join\s*\([^)]*request"],
            "javascript": [r"fs\.(readFile|readFileSync|createReadStream)\s*\(", r"res\.sendFile\s*\("],
            "php": [r"\b(file_get_contents|fopen|readfile|include|require)\s*\("],
            "java": [r"new\s+File\s*\(", r"Files\.(read|newInputStream)"],
            "go": [r"os\.(Open|ReadFile)\s*\(", r"ioutil\.ReadFile\s*\("],
        },
        "sanitizers": {"python": [r"os\.path\.basename", r"secure_filename", r"\.replace\([^)]*\.\."],
                        "javascript": [r"path\.basename", r"path\.normalize"]},
        "poc_hint": "Use `../../etc/passwd` (or `..\\..\\windows\\win.ini`); oracle: file contents leaked (e.g. `root:`).",
        "remediation": "对文件路径做规范化并限制在受信根目录内（resolve 后校验前缀）；拒绝 `..`/绝对路径；用白名单映射代替直接拼接。",
    },
    {
        "id": "ssrf", "cwe": "CWE-918", "name": "Server-Side Request Forgery",
        "severity": "high", "reproducible": True,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "sinks": {
            "python": [r"requests\.(get|post|put|delete|head)\s*\(", r"urllib\.request\.urlopen\s*\(", r"httpx\.(get|post)\s*\("],
            "javascript": [r"axios\.(get|post)\s*\(", r"fetch\s*\(", r"http\.get\s*\("],
            "php": [r"curl_exec\s*\(", r"file_get_contents\s*\(\s*\$"],
            "go": [r"http\.(Get|Post)\s*\("],
        },
        "sanitizers": {},
        "poc_hint": "Point the URL at an in-sandbox canary; oracle: canary receives the request (never egress to real network).",
        "remediation": "对出站 URL 做白名单/协议校验；解析后校验目标 IP 非私网/保留网段；禁用重定向跟随到内网；用带 SSRF 防护的代理。",
    },
    {
        "id": "xss", "cwe": "CWE-79", "name": "Reflected Cross-Site Scripting",
        "severity": "medium", "reproducible": True,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "sinks": {
            "python": [r"Response\s*\([^)]*request", r"return\s+f?[\"'][^\"']*\{",
                        r"[\"'][^\"']*<[^\"']*[\"']\s*\+", r"\+\s*request\.\w+", r"make_response\s*\([^)]*\+"],
            "javascript": [r"\.innerHTML\s*=", r"document\.write\s*\(", r"res\.send\s*\([^)]*req\.",
                            r"dangerouslySetInnerHTML", r"res\.write\s*\([^)]*req\."],
            "php": [r"\becho\s+.*\$_", r"\bprint\s+.*\$_", r"printf\s*\([^)]*\$_"],
        },
        "sanitizers": {"python": [r"escape\(", r"markupsafe", r"\|\s*e\b"],
                        "javascript": [r"escapeHtml", r"DOMPurify", r"textContent"]},
        "poc_hint": "Reflect `<script>...</script>` unescaped; static verification usually sufficient (hard to reliably auto-repro).",
        "remediation": "输出编码/转义（按上下文 HTML/JS/URL）；使用模板引擎自动转义；前端避免 innerHTML，改用 textContent 或 DOMPurify。",
    },
    {
        "id": "hardcoded-secret", "cwe": "CWE-798", "name": "Hardcoded Credentials / Secret",
        "severity": "medium", "reproducible": False,
        "cvss": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "sinks": {
            "*": [r"(?i)(api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*[\"'][A-Za-z0-9_\-/+]{12,}[\"']",
                   r"AKIA[0-9A-Z]{16}", r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"],
        },
        "sanitizers": {},
        "poc_hint": "N/A — static finding.",
        "remediation": "移除硬编码密钥，改用环境变量/密钥管理服务；轮换已泄露凭据；将敏感文件加入忽略清单。",
    },
]

VULN_RULES += [
    {
        "id": "ssti", "cwe": "CWE-1336", "name": "Server-Side Template Injection",
        "severity": "high", "reproducible": True,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "sinks": {
            "python": [r"render_template_string\s*\(", r"Template\s*\([^)]*request", r"env\.from_string\s*\("],
            "javascript": [r"\.compile\s*\([^)]*req\.", r"template\s*\([^)]*req\."],
        },
        "sanitizers": {},
        "poc_hint": "Inject `{{7*7}}` / `${7*7}`; oracle: evaluated result (49) appears in output.",
        "remediation": "不要用用户输入拼接模板；使用固定模板 + 上下文变量传参；沙箱化模板引擎并禁用危险内置。",
    },
    {
        "id": "open-redirect", "cwe": "CWE-601", "name": "Open Redirect",
        "severity": "medium", "reproducible": False,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "sinks": {
            "python": [r"redirect\s*\(\s*request", r"redirect\s*\([^)]*\+"],
            "javascript": [r"res\.redirect\s*\([^)]*req\.", r"location\.href\s*=\s*[^;]*req"],
            "php": [r"header\s*\(\s*[\"']Location:.*\$_"],
        },
        "sanitizers": {},
        "poc_hint": "Set the redirect target to an external URL; oracle: 302 Location points off-site.",
        "remediation": "对跳转目标做白名单/相对路径校验，拒绝外部绝对 URL 与协议相对 URL。",
    },
    {
        "id": "xxe", "cwe": "CWE-611", "name": "XML External Entity",
        "severity": "high", "reproducible": False,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "sinks": {
            "python": [r"etree\.parse\s*\(", r"etree\.fromstring\s*\(", r"xml\.dom\.minidom\.parse"],
            "java": [r"DocumentBuilderFactory", r"SAXParserFactory", r"XMLInputFactory"],
            "php": [r"simplexml_load_(string|file)\s*\(", r"DOMDocument"],
        },
        "sanitizers": {"python": [r"resolve_entities\s*=\s*False", r"defusedxml"]},
        "poc_hint": "Submit XML with an external entity; oracle: file/SSRF content reflected.",
        "remediation": "禁用外部实体解析（defusedxml / 设置 FEATURE_SECURE_PROCESSING、禁用 DOCTYPE）。",
    },
    {
        "id": "vulnerable-dependency", "cwe": "CWE-1395", "name": "Vulnerable Dependency",
        "severity": "high", "reproducible": False,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "sinks": {}, "sanitizers": {},
        "poc_hint": "See the referenced advisory (CVE/GHSA) for exploitation details.",
        "remediation": "升级到已修复版本；如无法升级，评估是否受影响并采取缓解/替换依赖。",
    },
]

# ----------------------------------------------------------------------------
# Logic-class rules — the "missing check" vulnerabilities (broken access control / IDOR,
# missing auth, CSRF, race, business logic, mass assignment). These are NOT detectable by a
# "dangerous sink" regex, so `sinks` is EMPTY (the regex scanner skips them). They are found
# by the framework-aware Hunter (semantic reasoning) + the logic heuristics, and CONFIRMED
# dynamically by the Validator using preheat role sessions + http_probe (access-control bugs
# are perfectly reproducible: log in as user A, try user B's object → IDOR, etc.).
# `how_to_spot` seeds the model's checklist; `class`/`detection` mark them for the pipeline.
# ----------------------------------------------------------------------------
VULN_RULES += [
    {
        "id": "broken-access-control", "cwe": "CWE-639", "name": "Broken Access Control / IDOR",
        "severity": "high", "reproducible": True, "class": "logic", "detection": "semantic",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "sinks": {}, "sanitizers": {},
        "how_to_spot": "路由按请求传入的 id 读取/修改对象，却不校验该对象归属当前用户（缺 owner/user_id 过滤）。",
        "poc_hint": "以用户 A 登录，把 URL/参数里的对象 id 换成用户 B 的 → 若能读到/改到 B 的数据即坐实（用预热的两个角色会话对比）。",
        "remediation": "对每个按 id 访问的资源强制做归属/权限校验（查询时按 current_user 过滤，或访问后校验 owner）；用集中式授权（Policy/Pundit/@PreAuthorize）。",
    },
    {
        "id": "missing-authentication", "cwe": "CWE-306", "name": "Missing Authentication",
        "severity": "high", "reproducible": True, "class": "logic", "detection": "semantic",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "sinks": {}, "sanitizers": {},
        "how_to_spot": "敏感/状态变更路由的处理函数上没有鉴权守卫（@login_required / Depends(auth) / 中间件 / @PreAuthorize）。",
        "poc_hint": "不带任何登录态直接请求该端点 → 若返回 2xx 且执行了敏感操作即坐实（用匿名会话 http_probe）。",
        "remediation": "对所有敏感/写端点强制认证与授权；默认拒绝，白名单放行公开端点。",
    },
    {
        "id": "auth-bypass", "cwe": "CWE-287", "name": "Authentication Bypass",
        "severity": "critical", "reproducible": True, "class": "logic", "detection": "semantic",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "sinks": {}, "sanitizers": {},
        "how_to_spot": "认证逻辑可被绕过：可预测/硬编码 token、用 == 比密码、信任客户端传入的 role/is_admin、JWT 未验签或 alg=none。",
        "poc_hint": "构造绕过条件（伪造 role 字段 / 空签名 JWT / 已知默认凭据）访问受限资源。",
        "remediation": "服务端强制校验身份与权限，绝不信任客户端提交的身份/角色；JWT 强制验签、禁 alg=none；用恒定时间比较。",
    },
    {
        "id": "csrf", "cwe": "CWE-352", "name": "Cross-Site Request Forgery",
        "severity": "medium", "reproducible": True, "class": "logic", "detection": "semantic",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "sinks": {}, "sanitizers": {},
        "how_to_spot": "基于 Cookie 会话的状态变更端点没有 CSRF token 校验（框架默认无/被 @csrf_exempt·disable 关闭），且未用 SameSite。",
        "poc_hint": "构造跨站自动提交的表单/请求（不带 CSRF token）→ 若操作成功即坐实。",
        "remediation": "对状态变更请求校验 CSRF token（框架内置保护）；Cookie 设 SameSite=Lax/Strict；关键操作二次确认。",
    },
    {
        "id": "race-condition", "cwe": "CWE-362", "name": "Race Condition / TOCTOU",
        "severity": "medium", "reproducible": True, "class": "logic", "detection": "semantic",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L",
        "sinks": {}, "sanitizers": {},
        "how_to_spot": "对共享状态先检查后动作却无锁/原子性（如查余额→扣款、查库存→下单、限领一次），并发下可被利用。",
        "poc_hint": "并发发起多个相同请求（并行 http_probe）→ 若出现超额扣减/重复领取即坐实。",
        "remediation": "用数据库事务 + 行级锁/乐观锁/唯一约束，或原子操作（compare-and-set）替代"
                       "\"读-判断-写\"，把校验与变更放在同一原子步骤。",
    },
    {
        "id": "business-logic", "cwe": "CWE-840", "name": "Business Logic Flaw",
        "severity": "medium", "reproducible": False, "class": "logic", "detection": "semantic",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
        "sinks": {}, "sanitizers": {},
        "how_to_spot": "业务规则可被滥用：负数/超大数量或金额、跳过必要步骤、重复使用一次性凭证、客户端定价、越权状态流转。",
        "poc_hint": "针对具体业务构造违规输入（负数量、改价格、跳步）验证是否被服务端接受。",
        "remediation": "在服务端强校验所有业务不变量（范围/符号/状态机/幂等），绝不信任客户端计算的价格/数量/权限。",
    },
    {
        "id": "mass-assignment", "cwe": "CWE-915", "name": "Mass Assignment",
        "severity": "high", "reproducible": True, "class": "logic", "detection": "semantic",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "sinks": {}, "sanitizers": {},
        "how_to_spot": "把整个请求体直接绑定/写回模型（create(request.all()) / 展开 req.body / Bind 结构体），"
                       "用户可注入不该设的字段（role/is_admin/owner_id/price）。",
        "poc_hint": "在请求体里附带 is_admin=true / role=admin / owner_id=<自己> → 若被采纳即坐实。",
        "remediation": "白名单允许写入的字段（strong params / $fillable / DTO 显式字段），绝不整体绑定请求体。",
    },
    {
        "id": "weak-crypto", "cwe": "CWE-327", "name": "Weak / Broken Cryptography",
        "severity": "medium", "reproducible": False,
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "sinks": {
            "python": [r"\bhashlib\.(md5|sha1)\s*\(", r"\bDES\b", r"MODE_ECB", r"random\.random\s*\(", r"random\.randint\s*\("],
            "javascript": [r"createHash\(\s*['\"](md5|sha1)", r"Math\.random\s*\(", r"\bDES\b", r"ECB"],
            "php": [r"\bmd5\s*\(", r"\bsha1\s*\(", r"MCRYPT_DES", r"ECB", r"\brand\s*\(", r"\bmt_rand\s*\("],
            "java": [r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-1)", r"DES", r"ECB", r"new\s+Random\s*\("],
            "go": [r"md5\.", r"sha1\.", r"math/rand"],
        },
        "sanitizers": {},
        "poc_hint": "N/A — 静态判定：安全敏感用途（口令哈希/令牌/加密）使用了弱算法或非密码学随机。",
        "remediation": "口令用 bcrypt/scrypt/argon2；哈希用 SHA-256+；加密用 AES-GCM（禁 ECB/DES）；令牌用 CSPRNG（secrets/crypto.randomBytes）。",
    },
]

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def rule_by_id(rid: str) -> Optional[dict]:
    for r in VULN_RULES:
        if r["id"] == rid:
            return r
    return None


def kb_lookup(query: str = "", vuln_type: str = "") -> List[dict]:
    """Backing store for the kb_search tool."""
    out = []
    q = (query + " " + vuln_type).lower()
    for r in VULN_RULES:
        hay = f"{r['id']} {r['cwe']} {r['name']}".lower()
        if not q.strip() or any(tok in hay for tok in q.split()):
            out.append({"id": r["id"], "cwe": r["cwe"], "name": r["name"],
                         "remediation": r["remediation"], "poc_hint": r["poc_hint"]})
    return out or [{"id": r["id"], "cwe": r["cwe"], "name": r["name"],
                     "remediation": r["remediation"], "poc_hint": r["poc_hint"]} for r in VULN_RULES[:3]]
