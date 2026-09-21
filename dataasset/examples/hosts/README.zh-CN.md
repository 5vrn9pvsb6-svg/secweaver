# 示例主机清单（公开示例）

**语言：** [English](README.md) | 简体中文（本文）

本目录存放公开示例用的合成主机记录。它们仅作为**参考模板**，不会进入 `dataasset/hosts/` 的离线 demo registry。

## 使用方式

- 复制某个文件后，将 `host_id`、`hostname`、`host_ip` 改成实验室值（RFC 5737 或 `10.10.x.x` / `10.20.x.x` 等私有演示网段）。
- 在维护者提升到 `dataasset/hosts/` 前，保持 `status: draft`。
- 任何 registry 提升后都运行 `make validate`。

## 精简 demo 主机

当前精简离线 registry 只保留：

| 文件 | 角色 |
|---|---|
| [`../../hosts/host-web-01.json`](../../hosts/host-web-01.json) | Web / Nginx 演示节点 |
| [`../../hosts/host-db-01.json`](../../hosts/host-db-01.json) | MySQL 演示节点 |
| 额外实验室主机条目 | 本地 auth.log 示例 |
