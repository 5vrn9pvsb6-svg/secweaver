# SLS Proxy Community 契约与安全边界

**语言：** [English](23-sls-proxy-multi-tenant-design.md) | 简体中文（本文）

本文定义 SecWeaver Community 接入托管 SLS Proxy 时的公开客户端契约和安全预期。Community 归档包含 `sls_proxy` Connector、Schema、示例和客户端测试，不包含 Proxy 服务端、控制面、生产凭证或服务端部署工具。

## 公开接入契约

Community 客户端配置：

- `connector_type: sls_proxy`；
- HTTPS 主 endpoint 和可选的备用 endpoint；
- Proxy API Key 的 credential 引用；
- 每个资产使用的逻辑 Logstore。

与公开 Connector 示例一致的托管服务配置为：

```json
{
  "name": "SecWeaver managed SLS Proxy",
  "endpoint": "https://sls-proxy.id-net.cn:30443",
  "fallback_endpoint": "https://sls-proxy.id-net.cn:30443"
}
```

当前示例的主、备用地址相同，客户端会去重，因此只使用一个入口；这不代表独立备用服务或高可用。仅在运营方提供兼容的独立备用入口时修改 `fallback_endpoint`。

请从 [`conn-sls-proxy-demo.json`](../dataasset/connectors/conn-sls-proxy-demo.json) 开始，并按 [SLS Proxy 接入指南](../docs_user/30-sls-proxy-onboarding.zh-CN.md) 操作。不要把 Proxy API Key 写入 Git 跟踪的 JSON。

## 安全不变量

任何兼容的 SLS Proxy 服务都必须满足以下可观察安全属性：

1. 查询上游数据源前先完成客户端鉴权。
2. 租户身份由服务端绑定，不能信任查询参数中传入的租户 ID。
3. 解析请求后强制注入租户过滤条件；无法安全约束的表达式必须拒绝。
4. 使用服务端独立保管的上游凭证，不能把客户端 API Key 转发给上游。
5. 限制查询时间范围、返回量、并发数和请求速率。
6. 对外返回通用鉴权错误，详细原因只写入受控审计日志。
7. 撤销客户端 Key 时不要求修改 Community DataAsset 文件。
8. 使用有效 HTTPS 证书，客户端不得关闭证书校验。

Proxy API Key 只用于访问 Proxy，它不是阿里云 AccessKey，也不能作为 AccessKey 使用。

## 数据隔离预期

Community 可以验证客户端协议和标准化响应契约，但无法证明托管服务内部的租户隔离。服务运营方必须独立验证跨租户拒绝、查询重写、密钥撤销、审计覆盖和上游凭证隔离。

空结果不能证明隔离正确。隔离验证必须使用两个受控租户同时执行允许访问和拒绝访问测试。

## 兼容性与失败行为

- 若配置独立备用 endpoint，它必须与主 endpoint 提供相同的客户端契约。
- 只有连接故障、超时或可重试服务端错误才能触发备用 endpoint；鉴权和参数校验错误不能通过故障转移重试。
- 证书、信任链、主机名或其他 TLS/SSL 失败应立即终止，不切换入口、不关闭验证；修复方法见 [TLS/CA 接入指南](../docs_user/30-sls-proxy-onboarding.zh-CN.md)。
- 查询必须限制在请求的调查时间窗口内。
- 所有已配置 endpoint 都不可用时，Skill 必须报告数据缺口，不能生成“未发现风险”的结论。

## 公开与私有职责

| Community 仓库 | 托管或私有交付 |
|---|---|
| Connector Schema 与示例 | Proxy 服务端实现 |
| 客户端请求和响应处理 | 租户和控制数据库 |
| DataAsset 与查询模板 | KMS/HSM 与上游 SLS 凭证 |
| 客户端契约测试 | 服务端隔离和部署测试 |
| 用户接入文档 | Operator CLI、备份和生产部署 |

该边界是有意设计的：开源仓库提供兼容客户端接入所需内容，服务端实现和运营能力由独立交付包负责验证。
