"""Framework security-model knowledge.

Each record captures HOW a web framework does the things that logic-class vulnerabilities
hinge on — routing, authentication/authorization, ORM (safe vs injection-prone), template
auto-escaping, CSRF defaults — plus a per-framework logic-vuln checklist. Two consumers:

  · human-readable guidance  -> injected into the Hunter/Validator prompts + the RAG KB, so
    the model audits with the framework's actual security model in mind (missing authz, IDOR,
    CSRF, …) instead of guessing.
  · machine `markers` (regex) -> used by the framework-aware logic-vuln heuristics
    (analysis.scan_logic_candidates) to seed low-confidence candidates deterministically.

Records are intentionally compact (enough to steer an LLM, not exhaustive docs). Extend by
adding a key here — everything downstream is data-driven.
"""
from __future__ import annotations

from typing import Dict, List

# state-changing HTTP methods — the routes where missing-auth / IDOR / CSRF matter most
STATE_CHANGING = ("post", "put", "delete", "patch")


FRAMEWORKS: Dict[str, dict] = {
    "flask": {
        "name": "Flask", "language": "python",
        "routes": "路由用 @app.route / @bp.route 装饰函数声明；HTTP 方法在 methods=[...]（默认 GET）。",
        "auth": "认证/授权通常靠 flask-login 的 @login_required + current_user，或自定义 before_request 守卫、"
                "手动查 session['user']。【缺失信号】状态变更/敏感路由的处理函数上没有 @login_required（或等价守卫）。",
        "orm": "SQLAlchemy 参数化查询/ORM 安全；db.session.execute(text(f\"...{x}\")) 或字符串拼接 SQL 危险。",
        "templating": "Jinja2 默认自动转义；{{ x|safe }} / render_template_string(用户输入) 关闭转义 → XSS / SSTI。",
        "csrf": "Flask 默认【不】带 CSRF 保护；需 Flask-WTF 的 CSRFProtect 全局启用或表单校验 csrf_token。"
                "【缺失信号】有 POST/PUT/DELETE 路由但项目未启用 CSRFProtect。",
        "notes": "app.run(debug=True) 暴露 Werkzeug 交互式调试器（可 RCE）；SECRET_KEY 硬编码 → session 伪造。",
        "logic_checks": [
            "每个状态变更/敏感路由：是否有 @login_required 等鉴权守卫？",
            "按 id 取对象（User.query.get(request.args['id']) / .filter_by(id=...)）时，是否又按 current_user 过滤归属？否则疑似 IDOR。",
            "POST 表单/写接口是否校验 CSRF token？",
        ],
        "markers": {
            "route": [r"@\w+\.(route|get|post|put|delete|patch)\b"],
            "method_post": [r"methods\s*=\s*\[[^\]]*(POST|PUT|DELETE|PATCH)", r"@\w+\.(post|put|delete|patch)\b"],
            "auth": [r"@login_required", r"\bcurrent_user\b", r"login_required", r"before_request",
                     r"session\.get\(\s*['\"]user", r"session\[['\"]user"],
            "object_by_id": [r"\.query\.get\(", r"\.query\.get_or_404\(", r"\.filter_by\(\s*id\s*=",
                             r"\.get\(\s*id\s*="],
            "ownership": [r"current_user", r"user_id\s*==", r"owner", r"\.filter_by\([^)]*user"],
            "csrf": [r"CSRFProtect", r"csrf_token", r"@csrf", r"csrf\.protect"],
        },
    },
    "django": {
        "name": "Django", "language": "python",
        "routes": "视图函数/类映射在 urls.py 的 urlpatterns；类视图继承 View/APIView。",
        "auth": "认证靠 @login_required / LoginRequiredMixin / @permission_required / request.user.is_authenticated；"
                "DRF 用 permission_classes。【缺失信号】敏感视图无这些守卫，或 permission_classes=[AllowAny]。",
        "orm": "Django ORM 参数化安全；.raw()、.extra()、字符串拼接的 filter 危险。",
        "templating": "Django 模板默认自动转义；{{ x|safe }} / mark_safe() / format_html 用户输入 关闭转义 → XSS。",
        "csrf": "Django 默认带 CsrfViewMiddleware（自带 CSRF 保护）。【缺失信号】@csrf_exempt 装饰的写视图 → CSRF 敞开。",
        "notes": "DEBUG=True 泄露堆栈/设置；SECRET_KEY 泄露 → 会话/签名伪造；ALLOWED_HOSTS='*' 风险。",
        "logic_checks": [
            "敏感/写视图是否有 @login_required / permission_classes？是否被 @csrf_exempt 关掉了 CSRF？",
            "get_object_or_404(Model, pk=request 参数) 后是否校验 request.user 拥有该对象？否则 IDOR。",
            "DRF 的 queryset 是否按 request.user 过滤（get_queryset），还是返回全量对象？",
        ],
        "markers": {
            "route": [r"path\(", r"re_path\(", r"url\(", r"as_view\("],
            "method_post": [r"def\s+(post|put|delete|patch)\s*\(", r"http_method_names", r"@require_(POST|http)"],
            "auth": [r"@login_required", r"LoginRequiredMixin", r"@permission_required", r"permission_classes",
                     r"request\.user\.is_authenticated", r"IsAuthenticated"],
            "object_by_id": [r"get_object_or_404\(", r"\.objects\.get\(\s*pk\s*=", r"\.objects\.get\(\s*id\s*=",
                             r"\.objects\.filter\(\s*id\s*="],
            "ownership": [r"request\.user", r"user\s*=\s*request\.user", r"\.filter\([^)]*user"],
            "csrf": [r"csrf", r"CsrfViewMiddleware"],
            "csrf_disabled": [r"@csrf_exempt", r"csrf_exempt"],
        },
    },
    "fastapi": {
        "name": "FastAPI", "language": "python",
        "routes": "路由用 @app.get/post/put/delete/@router.* 装饰；参数/依赖用类型注解 + Depends。",
        "auth": "认证/授权靠 Depends(get_current_user) / Security(...) / OAuth2 依赖。"
                "【缺失信号】状态变更路由没有鉴权依赖（无 Depends 校验身份）。",
        "orm": "SQLAlchemy/SQLModel 参数化安全；execute(text(f\"...{x}\")) 危险。",
        "templating": "多为 JSON API；若用 Jinja2Templates，注意 | safe。",
        "csrf": "纯 JSON API + Bearer token 一般不受 CSRF 影响；若用 Cookie 会话则需自行防 CSRF。",
        "notes": "把敏感字段直接从请求体 Pydantic 模型写回 DB → 批量赋值/越权字段（mass assignment）。",
        "logic_checks": [
            "每个写路由是否有鉴权 Depends？还是任何人都能调？",
            "按 id 取资源后是否校验属于 current_user？否则 IDOR。",
            "请求体模型是否包含 role/is_admin/owner 等不该由用户设定的字段（mass assignment）？",
        ],
        "markers": {
            "route": [r"@\w+\.(get|post|put|delete|patch)\b", r"@router\.(get|post|put|delete|patch)\b"],
            "method_post": [r"@\w+\.(post|put|delete|patch)\b", r"@router\.(post|put|delete|patch)\b"],
            "auth": [r"Depends\(", r"get_current_user", r"Security\(", r"OAuth2", r"HTTPBearer"],
            "object_by_id": [r"\.get\(\s*\w*id\s*[,)]", r"\.query\([^)]*\)\.get\(", r"session\.get\("],
            "ownership": [r"current_user", r"\.user_id", r"owner"],
            "csrf": [],
        },
    },
    "express": {
        "name": "Express", "language": "javascript",
        "routes": "路由用 app.get/post/... 或 router.*；中间件按顺序执行。",
        "auth": "认证/授权靠中间件（passport、express-jwt、自定义 requireAuth/isAuthenticated），或每个 handler 里查 req.user。"
                "【缺失信号】写路由没有鉴权中间件、handler 里也不查 req.user。",
        "orm": "参数化查询（Sequelize/Knex 绑定参数）安全；字符串拼接 SQL、Sequelize literal(用户输入) 危险。",
        "templating": "取决于引擎；EJS <%- %>、Handlebars {{{ }}} 不转义 → XSS；res.send 拼接用户输入 → XSS。",
        "csrf": "Express 默认无 CSRF；需 csurf 中间件。【缺失信号】有会话+写路由但无 csurf。",
        "notes": "原型污染（把用户 JSON 合并进对象）；req.body 直接传给 Mongo 查询 → NoSQL 注入。",
        "logic_checks": [
            "每个写路由链上是否有鉴权中间件？还是裸奔？",
            "按 id 取文档/记录（findById(req.params.id)）后是否校验属于 req.user？否则 IDOR。",
            "是否用 csurf 防 CSRF？req.body 是否被直接展开进查询（NoSQL 注入 / mass assignment）？",
        ],
        "markers": {
            "route": [r"\.(get|post|put|delete|patch)\s*\(\s*['\"]"],
            "method_post": [r"\.(post|put|delete|patch)\s*\(\s*['\"]"],
            "auth": [r"requireAuth", r"isAuthenticated", r"ensureAuth", r"passport", r"express-jwt",
                     r"\breq\.user\b", r"verifyToken", r"authMiddleware", r"authenticate"],
            "object_by_id": [r"findById\(", r"findByPk\(", r"\.findOne\(\s*\{\s*[_]?id",
                             r"\.get\(\s*req\.params"],
            "ownership": [r"req\.user", r"userId", r"owner"],
            "csrf": [r"csurf", r"csrfProtection", r"csrf\("],
        },
    },
    "spring": {
        "name": "Spring (Boot/MVC)", "language": "java",
        "routes": "@RestController/@Controller + @GetMapping/@PostMapping/@RequestMapping。",
        "auth": "Spring Security：SecurityFilterChain 规则、@PreAuthorize/@Secured、方法级授权。"
                "【缺失信号】写端点无 @PreAuthorize、或 SecurityConfig 用 permitAll()。",
        "orm": "JPA/命名参数安全；createQuery/createNativeQuery 字符串拼接、@Query 拼接 危险。",
        "templating": "Thymeleaf th:utext 不转义 → XSS；返回 HTML 拼接用户输入 → XSS。",
        "csrf": "Spring Security 默认对非 GET 开启 CSRF；.csrf().disable() 会关闭。【缺失信号】http.csrf().disable()。",
        "notes": "Actuator 端点暴露；SpEL 注入；反序列化 gadget。",
        "logic_checks": [
            "写端点是否有 @PreAuthorize/@Secured？SecurityConfig 是否 permitAll 敏感路径？",
            "按 id 查实体后是否校验归属当前 principal？否则 IDOR。",
            "是否 http.csrf().disable() 关掉了 CSRF？",
        ],
        "markers": {
            "route": [r"@(Get|Post|Put|Delete|Patch|Request)Mapping"],
            "method_post": [r"@(Post|Put|Delete|Patch)Mapping", r"method\s*=\s*RequestMethod\.(POST|PUT|DELETE|PATCH)"],
            "auth": [r"@PreAuthorize", r"@Secured", r"@RolesAllowed", r"SecurityFilterChain",
                     r"authenticated\(\)", r"hasRole", r"hasAuthority"],
            "object_by_id": [r"findById\(", r"getOne\(", r"getReferenceById\("],
            "ownership": [r"getPrincipal", r"getName\(\)", r"currentUser", r"\.getUserId"],
            "csrf": [r"csrf\(\)"],
            "csrf_disabled": [r"csrf\(\)\.disable\(\)", r"\.disable\(\)"],
        },
    },
    "rails": {
        "name": "Ruby on Rails", "language": "ruby",
        "routes": "config/routes.rb 声明；控制器动作（index/show/create/update/destroy）。",
        "auth": "认证/授权靠 before_action :authenticate_user!（Devise）、Pundit/CanCanCan 授权。"
                "【缺失信号】控制器无 before_action 鉴权、或写动作 skip_before_action。",
        "orm": "ActiveRecord 参数化安全；where(\"... #{x}\")、find_by_sql 拼接 危险。",
        "templating": "ERB 默认转义；raw()/html_safe/<%== %> 关闭转义 → XSS。",
        "csrf": "Rails 默认 protect_from_forgery（自带 CSRF）。【缺失信号】skip_before_action :verify_authenticity_token。",
        "notes": "strong parameters 缺失 → mass assignment；permit! 放开所有字段。",
        "logic_checks": [
            "控制器/写动作是否有 authenticate_user! 与授权(Pundit/CanCan)？",
            "Model.find(params[:id]) 后是否 scope 到 current_user？否则 IDOR。",
            "是否 skip 了 verify_authenticity_token？params 是否 permit! 全放开（mass assignment）？",
        ],
        "markers": {
            "route": [r"def\s+(index|show|create|update|destroy|new|edit)\b", r"resources\s+:"],
            "method_post": [r"def\s+(create|update|destroy)\b"],
            "auth": [r"before_action\s+:authenticate", r"authenticate_user!", r"authorize", r"policy_scope",
                     r"current_user"],
            "object_by_id": [r"\.find\(\s*params\[", r"\.find_by\(\s*id", r"\.where\(\s*id"],
            "ownership": [r"current_user", r"\.where\([^)]*user", r"user_id"],
            "csrf": [r"protect_from_forgery"],
            "csrf_disabled": [r"skip_before_action\s+:verify_authenticity_token"],
        },
    },
    "laravel": {
        "name": "Laravel", "language": "php",
        "routes": "routes/web.php|api.php 用 Route::get/post/...；控制器方法。",
        "auth": "认证靠 auth 中间件、$this->middleware('auth')、Gate/Policy 授权。"
                "【缺失信号】写路由/控制器无 auth 中间件、或 Policy 未校验。",
        "orm": "Eloquent/查询构造器绑定参数安全；DB::raw()、whereRaw(拼接) 危险。",
        "templating": "Blade {{ }} 默认转义；{!! !!} 不转义 → XSS。",
        "csrf": "Laravel 默认 VerifyCsrfToken 中间件（web 组自带 CSRF）。【缺失信号】$except 排除路由、或纯 api 无等价保护。",
        "notes": "mass assignment（$fillable/$guarded 配置不当 + Model::create($request->all())）。",
        "logic_checks": [
            "写路由是否挂 auth 中间件？Policy/Gate 是否校验归属？",
            "Model::find($request id) 后是否校验属于 auth()->user()？否则 IDOR。",
            "是否 Model::create($request->all()) 且 $guarded 为空（mass assignment）？",
        ],
        "markers": {
            "route": [r"Route::(get|post|put|delete|patch)\s*\("],
            "method_post": [r"Route::(post|put|delete|patch)\s*\("],
            "auth": [r"middleware\(\s*['\"]auth", r"->middleware\(", r"Gate::", r"authorize\(", r"auth\(\)->"],
            "object_by_id": [r"::find\(", r"::findOrFail\(", r"->find\(", r"where\(\s*['\"]id"],
            "ownership": [r"auth\(\)->", r"user_id", r"->user"],
            "csrf": [r"VerifyCsrfToken", r"csrf"],
        },
    },
    "gin": {
        "name": "Gin (Go)", "language": "go",
        "routes": "r.GET/POST/... 或路由组 group；中间件 r.Use()/group.Use()。",
        "auth": "认证/授权靠中间件（jwt、自定义 AuthRequired）或 handler 里查 context user。"
                "【缺失信号】写路由组无鉴权中间件。",
        "orm": "database/sql 占位符、GORM 参数化安全；fmt.Sprintf 拼 SQL、Raw(拼接) 危险。",
        "templating": "html/template 自动转义；text/template 用于 HTML → XSS。",
        "csrf": "无内置 CSRF；需自行中间件。",
        "notes": "c.Bind 把请求直接映射结构体 → 越权字段。",
        "logic_checks": [
            "写路由是否在带鉴权中间件的组里？",
            "按 id 取记录后是否校验属于当前用户？否则 IDOR。",
            "结构体绑定是否含 role/owner 等不该用户设的字段？",
        ],
        "markers": {
            "route": [r"\.(GET|POST|PUT|DELETE|PATCH)\s*\("],
            "method_post": [r"\.(POST|PUT|DELETE|PATCH)\s*\("],
            "auth": [r"AuthRequired", r"jwt", r"Authorize", r"c\.Get\(\s*['\"]user", r"middleware"],
            "object_by_id": [r"\.First\(", r"\.Where\(\s*['\"]id", r"\.Find\(", r"GetByID"],
            "ownership": [r"userID", r"user_id", r"c\.Get"],
            "csrf": [],
        },
    },
}

# framework name aliases produced by analysis._guess_frameworks / detect_stack
_ALIASES = {"flask": "flask", "django": "django", "fastapi": "fastapi", "express": "express",
            "spring": "spring", "rails": "rails", "laravel": "laravel", "gin": "gin",
            "react": None}   # react is frontend; no server-side security model here


def for_names(frameworks: List[str], languages: Dict[str, int] | None = None) -> List[dict]:
    """Select the framework records relevant to a project (by detected framework names)."""
    out, seen = [], set()
    for fw in frameworks or []:
        key = _ALIASES.get((fw or "").lower(), (fw or "").lower())
        if key and key in FRAMEWORKS and key not in seen:
            out.append(FRAMEWORKS[key])
            seen.add(key)
    return out


def guidance_block(records: List[dict]) -> str:
    """Compact framework-aware audit guidance for the Hunter/Validator prompts."""
    if not records:
        return ""
    parts = ["【框架安全模型（据此系统排查逻辑类漏洞：越权/IDOR、缺失鉴权、CSRF、竞态、业务逻辑）】"]
    for r in records:
        parts.append(
            f"· {r['name']}：鉴权={r['auth']} | ORM={r['orm']} | 模板={r['templating']} | CSRF={r['csrf']}"
            + (f" | 注意={r['notes']}" if r.get("notes") else ""))
        for chk in r.get("logic_checks", []):
            parts.append(f"    - 排查：{chk}")
    parts.append("提醒：逻辑类漏洞看的是【缺失的检查】（缺鉴权/缺归属校验/缺 CSRF），"
                 "不是危险函数——请对每个状态变更/敏感路由逐一核对上面清单，命中即 report_candidate。")
    return "\n".join(parts) + "\n"


def kb_entries() -> List[dict]:
    """Framework records as KB documents (for the RAG vuln-knowledge index)."""
    out = []
    for r in FRAMEWORKS.values():
        text = (f"{r['name']} 安全模型。路由：{r['routes']} 鉴权：{r['auth']} ORM：{r['orm']} "
                f"模板：{r['templating']} CSRF：{r['csrf']} 注意：{r.get('notes', '')} "
                f"逻辑漏洞排查：{' '.join(r.get('logic_checks', []))}")
        out.append({"id": f"framework-{r['name']}", "name": f"{r['name']} 框架安全模型", "text": text})
    return out
