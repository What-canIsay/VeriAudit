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
