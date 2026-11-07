# specvet · 中文说明

[English README](README.md) · OpenAPI / Swagger 的**安全**审查（不是风格检查）。

**一句话**：某个 path 的 GET 有认证、DELETE 没有——单看任意一条都合规，
合起来就是越权。第二遍扫描看的是关系。

## 为什么存在

[Spectral](https://github.com/stoplightio/spectral)（约 3.2k★）、Redocly、vacuum
管的是「API 描述写得规不规范」：命名、描述、示例、格式。安全语义的 cherrybomb
（约 1.2k★）是 Rust。零依赖 Python、把 36 条规则逐条映射到
**OWASP API Top 10 2023**、且做关系分析的赛道空着。

三个典型判断：

- `security` 定义了 scheme 却没有任何 operation 引用（定义了 ≠ 用上了）；
- 同一个资源 path 上，读操作挂了认证、写操作没挂；
- 字段`未声明`与`声明为空`是两件事：前者是覆盖缺口，后者通常是明确的设计。

## 三步跑通

```bash
# 1) 安装（零运行时依赖）
pip install git+https://github.com/xuange-hu/specvet

# 2) 看规则 / 生成一份故意写坏的规范（demo 打印到 stdout，实测 "36 of 36 rules"）
specvet rules
specvet demo > api.yaml

# 3) 查看认证覆盖、扫规范文件，并卡 CI（实测 SARIF 2.1.0 / 72 results）
specvet coverage api.yaml
specvet scan ./api --fail-on high -f sarif -o specvet.sarif
```

`specvet demo` 已在干净目录实测：`rc=0`，输出 203 行，打印一份故意写坏的规范。

## 差异化

| 能力 | 说明 |
|---|---|
| **36 规则全映射** | 每条对应 OWASP API Top 10 2023 的一个条目 |
| **两遍扫描** | pass 1 逐条检查，pass 2 看同一 path / 不同方法之间的关系 |
| **absent ≠ empty** | 区分「没写」与「写了空」，避免把覆盖缺口当成设计选择 |
| **每规则一个触发样本** | CI 断言 demo 覆盖 **36/36** |
| **MCP 6 工具** | `uvx --from "specvet[mcp]" specvet-mcp` |

## 命令

| 命令 | 作用 |
|---|---|
| `specvet scan PATH` | 审一个规范文件或目录树 |
| `specvet rules` | 列出规则集（带 OWASP 编号与级别） |
| `specvet demo` | 打印故意写坏的规范及其报告 |
| `specvet coverage FILE` | 该规范的认证覆盖视图 |

## 已知边界

- 静态审查，不向真实 API 发请求，无法验证服务端是否按规范执行；
- 规范与实现漂移时，以规范为准——这不是运行时 WAF；
- YAML 子集解析器保留行号，但不覆盖全部 YAML 1.2 特性。

贡献见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题见 [SECURITY.md](SECURITY.md)。MIT。
