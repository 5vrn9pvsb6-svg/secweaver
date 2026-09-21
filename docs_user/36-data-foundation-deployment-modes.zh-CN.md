# SecWeaver 数据底座四种部署模式

**语言：** [English](36-data-foundation-deployment-modes.md) | 简体中文（本文）

SecWeaver 的分析、关联和溯源建立在治理好的安全数据底座上。交付时先确定
底座模式，再接入 Connector、DataAsset 和调查场景。当前支持四种模式。

Community 用户默认推荐 SaaS SLS Proxy；已有自建 ES 时可使用下方公开接入路径。
前两种是由部署方管理的数据底座形态。Community 提供数据接入合同，但不包含这两种
底座的安装与运维工具；用户可将 SecWeaver 接到自行准备的兼容 ES/OpenSearch 服务。

## 1. 选型总表

| 模式 | 数据位置 | 底座责任方 | 客户侧安装 | 适用场景 | Community 包含范围 |
|---|---|---|---|---|---|
| 笔记本便携 ES | 部署方笔记本 | 部署方 | 业务主机安装 Agent + Filebeat | 应急、演练、隔离网、短期驻场 | 含客户端接入；底座安装与运维由部署方负责 |
| Linux 服务器 ES | 客户 Linux 服务器 | 客户运维/部署方 | 服务器准备兼容底座；主机安装 Agent + Filebeat | 私有化、长期运行、数据不出域 | 含客户端接入；底座安装与运维由部署方负责 |
| 客户自有 ES/OpenSearch | 客户现有集群 | 客户平台团队 | 不重复安装 ES，SecWeaver 只读接入 | 复用存量日志平台 | 含客户端接入；ES/OpenSearch 由用户自备 |
| Data Cloud 托管 SLS | SecWeaver Data Cloud | SecWeaver 平台团队 | 按需安装 Agent/Logtail | 最快上线、持续托管和字段治理 | 含 Proxy 客户端与 Agent；托管服务及账号另行开通 |

快速判断：现场临时或隔离网选笔记本；数据不出域且长期运行选 Linux 服务器；
已有成熟 ES 选客户自有 ES；希望减少建设和持续治理工作选 Data Cloud。
四种模式可以混合，但一个项目应指定一个主要查询底座。

## 2. 模式一：笔记本便携 ES

笔记本运行 SecWeaver、兼容的 ES/OpenSearch 查询服务、HTTPS Gateway、UI 和 Skill；
业务主机运行 `secweaver-agent` 和 Filebeat。具体端口由部署方的 Gateway 配置决定。

该模式把治理底座、UI 和调查 Skill 放在部署方笔记本，业务主机只运行 Agent 和批准的
输送器。Community 可以连接已经准备好的兼容查询服务；底座安装、离线缓冲、容量和恢复
流程由该环境的部署方负责，并应在上线前单独验收。

## 3. 模式二：Linux 服务器 ES

该模式在客户 Linux 服务器长期运行兼容的 ES/OpenSearch 服务和 HTTPS Gateway。
Community 可以通过公开 Connector 接入；服务器安装、TLS、容量、备份、回滚和升级
由客户运维或其部署方负责。

### 3.1 容量与运营边界

容量规划、磁盘保护阈值、JVM/分片配置、压测、备份和回滚都是环境特定决策。
Community 文档只定义接入与验收边界，不提供通用的一键底座安装方案；部署方必须根据
实际数据量、保留期和可用性要求完成设计与演练。

## 4. 模式三：客户自有 Elasticsearch / OpenSearch

该模式不重复部署 ES。数据保留在客户集群，SecWeaver 保存 SOPS 加密的只读凭证、
Connector、字段契约和查询模板。

先按[数据源配置指南](03-configure-data-sources.zh-CN.md)初始化 Python 环境并准备查询凭证；默认编辑 `dataasset/`，也可复制到 `dataasset_my/` 并设置 `DATAASSET_ROOT` 隔离使用。准备完成后，从仓库根目录启动：

```bash
DATAASSET_UI_PORT=8765 make ui
```

打开 `http://127.0.0.1:8765/onboarding.html` 的“接入客户自有 Elasticsearch”：

1. 输入 HTTPS endpoint 和只读 Basic/API Key；探测和生成的 ES Connector 默认校验证书。
   私有 CA 填写 `ca_file`，相对路径以 `DATAASSET_ROOT` 为基准；证书错误不会自动降级。
2. 依次执行“检测集群”“识别字段”“接入并激活”。
3. 平台通过索引发现、`_field_caps` 和 `_search` 验证后生成三件套。
4. 按[查询验收与启用](03-configure-data-sources.zh-CN.md#查询验收与启用)填写实际 Asset、测试目标与时间窗，验证已知事件和字段。仅生成配置或返回空结果不算验收通过。

UI 会占用当前终端；执行验收命令前按 Ctrl+C 停止，或另开终端并重新设置所选 `DATAASSET_ROOT`。所有 CLI、UI 和智能体查询都使用同一个资产目录。

这条流程接入的是**已有数据**，向导不会修改客户集群或下发采集器。新 Agent 数据写入
自建 Elasticsearch 的公开初始化脚本、安装脚本、Filebeat 配置和验收步骤见
[Agent 接入自建 ES](../src/tools/secweaver-agent/elasticsearch/README.zh-CN.md)。该示例面向 Linux +
ES 8.x，不需要 Operator；OpenSearch 需另行选用兼容输送器。

## 5. 模式四：SecWeaver Data Cloud 托管 SLS

SLS 存储、字段治理和 SLS Proxy 由 Data Cloud 托管。用户不接触正式 SLS RAM Key。
只有需要主机数据时才安装 Agent/Logtail；WEB/网关告警和网关访问日志可直接接入。

这里的“托管”和“自建”要区分清楚：Data Cloud 托管模式下，SecWeaver 平台团队负责
控制面、上游 SLS 权限、Project/Logstore、租户隔离索引、采集规则、机器组、DNS、TLS
和服务发布，客户主机只执行企业工作台生成的 Agent 命令。企业若自行运行兼容 Proxy，
则由其平台管理员负责这些服务端配置和运营工作，不能把它理解为零配置部署。

Data Cloud 会在托管服务就绪后签发带租户参数的 Agent 命令，并负责 endpoint、凭证、TLS
和发布元数据。Community 只承诺公开的 Agent、Proxy 客户端合同与接入模板，不包含服务端
安装和托管运营流程；自建兼容服务时应由平台管理员另行制定部署、证书和运维方案。

完整主机、WEB/网关、DNS 和资产接入见
[SecWeaver 数据系统快速搭建](29-secweaver-data-system-quickstart.zh-CN.md)；Proxy 见
[SLS Proxy 用户接入指南](30-sls-proxy-onboarding.zh-CN.md)。

## 6. 统一验收标准

1. **可采集**：真实事件进入目标存储，时间、来源和资产类型正确。
2. **可查询**：只读 Connector 能在小时间窗返回数据，密钥不进入资产 JSON。
3. **可理解/关联**：Asset 声明真实字段、时间字段和必要别名。
4. **可治理**：明确保留、延迟监控、凭证轮换、备份/SLA 责任人。
5. **可调查**：至少运行一次目标 Skill，报告能给出证据和数据缺口。

```bash
.venv/bin/python src/secweaver.py validate
```

不能仅凭“端口能连接”宣布交付完成，必须用真实事件完成采集、查询和调查闭环。
