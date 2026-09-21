# 数据资产校验建议参考

## 关键契约

- `status=active` 的 asset 才被视为可用。
- `status=active` 的 bundle 不得引用 draft/discovery/disabled 资产。
- connector 只保存非敏感 `config` 和 `credentials_ref`，真实密钥在 SOPS Vault。
- 资产侧不再使用 `host_binding`；主机覆盖用 `coverage.hosts` 日志来源 IP，单主机采集目标用 `connector.config.host_id`。
- `pii_fields` 只是治理标注；runtime 脱敏只看 `masking`。
- `correlation_keys` 不再手写，由 matrix + fields 推导。

## 发布前建议

1. `validate.py` 0 error。
2. active connector 有真实 config，不是 `YOUR_*` 占位。
3. active asset 有可用 `query_template_ids`。
4. active bundle 成员全 active。
5. 从仓库根目录先预览查询计划；`--dry-run` 不解密凭证，也不证明真实连通性：

```bash
python3 src/dataasset/test_connector.py asset-sls-proxy-host-exec-demo --by-asset --dry-run \
  --params '{"time_start":"2026-06-21T09:00:00+08:00","time_end":"2026-06-21T10:00:00+08:00"}'
```

真实数据验收时，将资产 ID 替换为已配置的授权资产、设置相应 `DATAASSET_ROOT`，再去掉 `--dry-run` 做只读连通测试。
