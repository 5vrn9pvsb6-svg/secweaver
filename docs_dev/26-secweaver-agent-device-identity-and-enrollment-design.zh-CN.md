# SecWeaver Agent 设备身份：公开客户端契约

**语言：** [English](26-secweaver-agent-device-identity-and-enrollment-design.md) | 简体中文（本文）

本文说明公开的 Agent 设备身份与注册客户端契约。Community 包含 Agent 实现和本地生命周期
行为；托管注册服务、设备额度管理、控制面存储和运营工具不属于 Community 仓库范围。

## 身份属性

- 设备身份只生成一次，并保存在可替换程序目录之外。
- 正常重启和升级复用原身份，不创建新设备。
- 私钥不离开设备；注册只发送公钥和有范围限制的设备元数据。
- 升级与卸载流程不得静默覆盖或删除身份目录。
- 本地身份状态丢失后，Agent 会生成新身份，服务端可能要求运营人员替换原设备记录。

Agent 包的权威版本来自 [`VERSION`](../src/tools/secweaver-agent/VERSION)。文档中的版本样例不能视为当前安装版本。

## 注册边界

托管注册使用短期或有使用次数限制的 enrollment token 注册 Agent 公钥。注册成功后，日常请求使用设备绑定签名，不再重复发送 enrollment token。

客户端必须：

1. 在本地生成密钥对；
2. 使用操作系统权限保护身份文件；
3. 校验 HTTPS 证书；
4. 按协议签名准确的请求方法、路径、时间戳、nonce 和请求体摘要；
5. 拒绝签名或目标设备身份不正确的配置与升级响应；
6. 不记录 enrollment token、私钥或完整 Authorization Header。

服务端必须拒绝过期 token、重复 nonce、过大时间偏差、已禁用设备和已撤销密钥签名。
这些是协议要求；托管服务实现和存储不属于 Community 仓库范围。

## 生命周期预期

| 事件 | Agent 预期行为 |
|---|---|
| 进程或主机重启 | 复用设备身份 |
| 已签名 Agent 升级 | 保留设备身份和本地回滚状态 |
| 硬件变化 | 保持身份不变，按配置报告有限硬件观察值 |
| 身份目录丢失 | 生成新身份，并由服务端完成设备记录核对 |
| 虚拟机克隆 | 制作模板时移除身份，使每个克隆首次启动时独立注册 |
| 设备或密钥撤销 | 停止接受属于该身份的托管配置和升级响应 |

硬件观察值不得包含原始 Secret，并应尽量减少持久硬件标识。硬件信息只能作为风险信号，不能作为唯一鉴权因素。

## Community 验证范围

Community 贡献者可以通过 Agent 测试验证本地身份持久化、文件权限、签名、升级保留、
回滚和异常响应处理。托管注册的端到端测试需要获授权的测试租户和测试凭证；这些服务端
资源不包含在 Community 仓库中。

构建和测试命令见 [`secweaver-agent` 工程手册](../src/tools/secweaver-agent/README.zh-CN.md)；托管安装路径见 [Data Cloud 客户快速上手](../docs_user/29-secweaver-data-system-quickstart.zh-CN.md)。
