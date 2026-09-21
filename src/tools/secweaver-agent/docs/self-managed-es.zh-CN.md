# 使用 Agent 发布包接入自建 Elasticsearch

[English](self-managed-es.md) | 简体中文

本页是发布包内导航。完整初始化、账号分工、CA、Filebeat 配置与入库验收步骤统一维护在 [Elasticsearch 接入指南](../elasticsearch/README.zh-CN.md)，解压包内可直接打开，无需源码检出。

适用：Linux systemd、Elasticsearch 8.x、Filebeat 8.19.x。ES、Filebeat、可信 HTTPS 证书及初始化/写入/只读账号由用户准备；该路径不需要 SaaS SLS Proxy 或私有服务端。

## 从哪里开始

1. 在解压后的发布包根目录运行 `python3 elasticsearch/init_es.py`，离线预览模板。
2. 按完整指南使用初始化账号创建模板，遇到配置漂移先审阅差异；不要覆盖现有索引。
3. 配置 Filebeat 的输入、keystore 和 CA，验证配置与输出，再启用采集。
4. 使用独立只读账号运行指南中的 `--check` 命令；没有近期事件、超时或分片失败均不算验收通过。

包内 `elasticsearch/` 包含 `init_es.py`、`index-template.json`、`filebeat.yml` 与双语 README。不得把生产凭证放进发布包。修改或升级 Filebeat 时保留 registry 与 `path.data`，避免重复读取。
