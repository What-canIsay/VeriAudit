# 精确 PoC（漏洞代码路径确认后本应可触发，但路由未注册）
# 请求方法：POST
# URL：http://127.0.0.1:8443/benchmark/xpathi-00/BenchmarkTest00104
# Body：BenchmarkTest00104=' or '1'='1
# 预期响应：返回所有员工信息（盲注探测其他 XPath 表达式也可行）
# 实际状态：HTTP 405/404（因模块语法错误，路由未注册）
# 
# == 代码证据 ==
# 第31行：param = request.form.get("BenchmarkTest00104")   ← 用户输入源
# 第40-42行：ConfigParser 存储/读取，无任何净化
# 第50行：query = f'/Employees/Employee[@emplid=\'{bar}\']'  ← 直接嵌入 XPath
# 第51行：run_query = lxml.etree.XPath(query)               ← 执行带注入的 XPath
# 
# 语法错误位置（第58行，无关漏洞本身）：
# f'Your XPATH query results are: <br>[ {', '.join(node_strings)} ]'
# → Python 3.11 不支持 f-string 内使用与外围相同的引号