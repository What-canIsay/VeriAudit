# 任务：为指定项目构建一个可交给 VeriAudit 使用的 CodeQL 数据库

你是一个精通 CodeQL 的工程助手。请帮我为下面这个项目构建一个 **CodeQL 数据库目录**，
这个目录会被我原样交给 VeriAudit（一个代码审计系统）的“手动调用图 → CodeQL DB”入口使用。
VeriAudit 会从 codeql-database.yml 读出语言，并用它自己内置的 calls.ql / dataflow.ql 对这个 DB
跑调用图和污点分析——**所以你只需产出完整可用的 DB，不需要、也不要写任何 CodeQL 查询。**

## 输入
- 项目源码路径（本地）：<D:\path\to\project>
- 期望输出 DB 目录：<D:\cg\proj-db>

## 必须满足的硬约束
2. **语言必须在 VeriAudit 支持列表内**：python、javascript（含 typescript，DB 语言标记即 javascript）、
   java、csharp、cpp、go、ruby。若主语言不在此列（如 PHP），请**停下来告诉我**——这条路走不通，改用
   JSONL 交付方式。
3. **整仓构建**：覆盖项目全部源码（不要只建一个子目录，除非我明确要求）。
4. **完整 finalize**：`codeql database create` 会自动 finalize；构建必须成功（退出码 0），
   且生成的目录里要有 `codeql-database.yml`、`db-<lang>/` 数据集目录、`src.zip`。

## 步骤（可能不全或有微小错误，需结合具体情况）
1. **识别主语言**（按源码文件占比 + 构建文件：pom.xml/build.gradle→java、*.csproj/*.sln→csharp、
   go.mod→go、Gemfile→ruby、CMake/Makefile/*.cpp→cpp、requirements/*.py→python、package.json/*.ts→javascript）。
   把判断依据告诉我。
2. **选择构建策略**（编译型语言的构建命令是成败关键）：
   - python / ruby / javascript·typescript：**解释型，免构建**，不需要 --command。
   - java：优先 `--build-mode=none`（免构建、源码提取，CodeQL≥2.16 支持）；若该项目需要生成代码/注解处理，
     再改用真实构建 `--command="mvn -q -DskipTests compile"` 或 `--command="./gradlew compileJava -x test"`。
   - csharp：优先 `--build-mode=none`；否则 `--command="dotnet build"`。
   - go：`--command="go build ./..."`（需要 go 工具链在 PATH；依赖需能拉取或已 vendor）。
   - cpp：**必须给能完整编译整个项目的真实命令**，如 `--command="cmake --build build"` 或
     `--command="make"`；CodeQL 靠追踪编译器提取，构建不全 = DB 不全。
3. **建库**（用 --overwrite 以便重跑）：
   codeql database create "<D:\cg\proj-db>" --language=<lang> --source-root="<D:\path\to\project>"
       [--build-mode=none | --command="<构建命令>"] --overwrite
4. **验证完整性**：确认命令退出码 0；`<db>\codeql-database.yml` 里 `primaryLanguage:` 是期望语言；
`<db>\db-<lang>\` 存在；`log/` 里没有致命 extractor 错误。可选：跑一个自带查询冒烟一下，
例如 `codeql database analyze <db> --format=csv 