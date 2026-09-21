# Bootstrap 动态安装版本

Agent 源码 0.3.21 移除 Linux/Windows Bootstrap 的固定安装版本。固定安装 URL 每次读取
`https://agent-gateway.id-net.cn:30443/secweaver-agent/releases/latest-version.txt`，
解析一次版本后下载对应不可变目录中的安装包和 SHA-256 文件。保留 `--version` / `-Version`
用于受控测试，普通用户不需要填写版本。

版本文件为最多 64 字符的 ASCII 版本，可带一个结尾 LF。缺失、为空、非法或不可达时，
在修改主机前停止，不回退到旧版本。首次安装的信任机制仍为 HTTPS 发布和安装包 SHA-256，
该版本文件本身没有独立签名；安装后的升级仍验证签名清单。此入口仅决定新安装版本，
不会强制升级存量设备。

Linux 支持 amd64/arm64/loong64，要求 Bash、curl/wget、tar、SHA-256 工具、coreutils
和 systemd。Windows 支持 amd64/arm64，要求管理员 PowerShell 5.1+；不支持 macOS。
版本入口必须使用 `no-store`，不能缓存旧值。

## 发布操作

### 注册设备身份（0.3.22）

Linux 安装器从同一次成功注册中取得企业 ID 和自动更新设备 ID。只传企业令牌时
无需 `--update-device-id`；显式传入冲突值会拒绝继续。旧企业 ID 安装方式启用更新时
仍需显式更新设备 ID。本修复不改变 Windows 行为。

`secweaver-agent enroll` 默认仍只向 stdout 输出企业 ID；`-output installer`
在身份落盘后输出严格的 `enterprise_id<TAB>device_id<LF>`。非法输出格式在注册前拒绝，
不输出私钥或令牌。安装脚本必须搭配同一发布的二进制，旧二进制不支持此选项。

授权状态和私钥路径显式使用 `STATE_DIR`。使用同一状态及私钥重试会复用设备身份；
部分安装失败后保留 `data/license-state.json` 和 `data/device-ed25519.key`。
注册后的安装错误不会撤销服务端注册，不要通过删除本地身份绕过设备额度。

在 Agent 目录运行 `go test -race . ./pkg/agentlicense`。测试覆盖真实 TLS 注册输出、
重试身份稳定性，以及隔离 Bash 安装的仅令牌、一致/冲突 ID、畸形输出、注册失败和
旧安装方式。这不等于真实 SLS 上传验收。该修复从 0.3.22 开始提供。发布当前版本的新不可变包、提升动态版本
指针后，在受控 Linux 测试主机上验证仅令牌安装、设备身份复用和上传链路；仅改外层 Bootstrap 不能修复旧 0.3.19 包内的安装器，禁止覆盖旧包。

先将五个平台审核过的安装包和校验文件以原始不可变字节发布到 `<release-root>/<version>/`，再执行：

```bash
python3 scripts/publish-release-channel.py --release-root /srv/secweaver-agent/releases --version <审核过的版本>
```

工具验证全部平台的名称、哈希、大小、权限和非符号链接条件后，原子替换 `latest-version.txt`。
失败保留旧指针。整个目录应归发布者所有，发布操作需串行。可显式把新安装入口切回较旧版本，
但已安装设备仍必须走签名授权的回滚流程，不能用修改指针绕过。

只重新生成 Bootstrap 时，保留正常 `BOOTSTRAP_*` 配置，设置 `BOOTSTRAP_ONLY=1`、
`BOOTSTRAP_UPDATE_PUBLIC_KEY_FILE=<已有公钥路径>`、`OUT_DIR=<全新输出目录>` 后运行
`./scripts/package-release.sh`。此模式不需要签名私钥，也不重建 Agent 包；源码版本和来源
门禁仍生效，脏构建仅用于测试。不能静默更换现有升级信任公钥。
普通打包不会自动提升线上安装版本；必须在真实服务目录的全部包就绪后显式提升。

Agent Gateway（服务端 rc.8+）通过白名单提供 `AGENT_RELEASE_ROOT/releases/latest-version.txt`；
查询服务不会提供此路径。安装脚本、版本目录、配置好的 Logtail 安装脚本及有效签名升级资源
全部发布并验收后，才能声明完整安装/升级可用。

## 验证

仓库根目录执行 `python3 -m unittest tests.test_secweaver_agent_wrappers tests.test_agent_release_channel`，
覆盖 Linux 动态选择、显式版本、缺失/非法入口和提升失败保护。服务端 `TestReleaseVersionPointer`
覆盖 GET/HEAD、no-store、非法内容和查询端隔离。Windows 仍需真实主机验证语法与安装流程，
源码检查不等于 Windows 验收。
