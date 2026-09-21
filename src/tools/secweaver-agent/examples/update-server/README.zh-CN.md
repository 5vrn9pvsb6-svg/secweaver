# Standalone 升级服务器示例

[English](README.md) | 简体中文

本例只描述**已有 standalone Agent 的升级**。静态 HTTPS 服务发布签名 manifest 和二进制，设备根据 manifest 灰度。托管 SaaS/ES 控制面仍要求服务端资格和租约，不应复制此处的 `require_server_policy: false`。

## 前提与平台

构建机需要 Go（版本见模块 `go.mod`）、Python 3、Bash、干净 Git 检出和离线保管的 Ed25519 发布密钥。脚本构建 Linux amd64/arm64/loong64 与 Windows amd64/arm64；本目录的 nginx 与客户端路径示例面向 Linux。Windows 必须使用对应服务安装路径并完成实际 SCM 升级、重启和健康回滚验收；交叉编译不能代替验收。

初装、授权与采集配置见 [Agent README](../../README.zh-CN.md)。本例不生成托管企业安装命令，也不部署 SaaS 服务端。

## 构建签名升级文件

修改 Agent 源码、打包配置或文档后，先递增 `../../VERSION` 并提交。构建读取 canonical VERSION，禁止用环境变量另取版本，也禁止在同一版本下发布不同内容。参见 [release.env.example](release.env.example)。以下命令从仓库根目录开始；私钥仅第一次创建：

```bash
cd src/tools/secweaver-agent
# One-time key creation; never overwrite an existing release key.
go run ./cmd/update-sign -generate-key /secure/path/update-signing.key

UPDATE_SIGNING_PRIVATE_KEY_FILE=/secure/path/update-signing.key \
UPDATE_BASE_URL="https://updates.example.com/secweaver-agent/releases/$(cat VERSION)" \
UPDATE_MANIFEST_GENERATION="${RELEASE_GENERATION:?Set a fresh monotonic integer}" \
UPDATE_MANIFEST_EXPIRES_AT="${RELEASE_EXPIRES_AT:?Set a future RFC3339 UTC expiry}" \
UPDATE_ARTIFACT_SIGNATURE_FORMAT=ed25519-sha256 \
UPDATE_ROLLOUT_PERCENTAGE=10 \
UPDATE_DOWNLOAD_SPREAD_SECONDS=3600 \
./scripts/build-cross.sh
```

私钥权限保持 `0600`，不能上传到静态服务器或仓库。客户端通过可信安装渠道获得 `.pub` 公钥。每个新 manifest 使用更大的 generation 和有效到期时间；不能用同一 generation 签发不同内容。当前默认二进制签名为 `ed25519-sha256`，旧客户端的过渡升级需单独验证兼容性。缺少私钥或版本门禁失败时应修复构建输入，不绕过检查。

## 静态服务布局

构建输出在 Agent 的 `dist/`。复制 `secweaver-agent_<VERSION>_<platform>` 二进制（Windows 为 `.exe`）到对应不可变版本目录，再原子替换 stable manifest：

```text
/srv/secweaver-agent-updates/
├── stable/update-manifest.json
└── releases/<VERSION>/secweaver-agent_<VERSION>_<platform>
```

使用 [nginx 配置](nginx-secweaver-agent-updates.conf) 配置有效证书，验证 manifest 的每个下载 URL 指向同一版本、大小和 SHA-256 对应的文件。保存 `dist/SOURCE.commit` 和 `dist/SOURCE.sha256` 作为构建记录。静态目录不得包含签名私钥。

## 客户端配置

合并 [client-config.example.json](client-config.example.json) 的 `update` 块到已有配置；不要覆盖现有 modules 和采集路径。替换公钥与每台设备稳定唯一的 `device_id`，确认 `manifest_url` 为 `/secweaver-agent/stable/update-manifest.json`。

本例 `require_server_policy=false` 仅适用于 standalone；`enabled=false` 时不自动联网，`auto_install=false` 可先只检查升级。健康超时、锁、备份和磁盘余量字段见示例。默认 6 小时检查间隔不等于发布时间后立即升级。

## 灰度与验收

从 `0% + allow_device_ids` 小范围开始，再扩至 10%、30%、50%、100%；`deny_device_ids` 优先拒绝，`download_spread_seconds` 按稳定设备身份分散下载。变更 manifest 内容需重新签名与递增 generation。

替换公钥和设备 ID 后执行：

```bash
secweaver-agent update check \
  -manifest-url https://updates.example.com/secweaver-agent/stable/update-manifest.json \
  -public-key BASE64_ED25519_PUBLIC_KEY \
  -device-id swd_IMMUTABLE_DEVICE_ID
```

`rollout_deferred` 表示未命中灰度，不是安装失败；`update_available` 表示可用版本，不是升级完成。随后在授权测试主机验证安装、服务重启、日志持续写入和健康失败回滚，再扩大范围。证书、签名或过期检查失败应停止并修复发布内容，不关闭校验。
