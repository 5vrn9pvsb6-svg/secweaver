# Example Host Inventory (public examples)

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

Synthetic host records for public examples. They are **reference templates only** and are not part of the curated offline demo registry in `dataasset/hosts/`.

## Usage

- Copy a file, rename `host_id` / `hostname` / `host_ip` to lab values (RFC 5737 or private demo ranges such as `10.10.x.x` / `10.20.x.x`).
- Keep `status: draft` until a maintainer promotes the record into `dataasset/hosts/` for curated demos.
- Run `make validate` after any registry promotion.

## Curated Demo Hosts

The curated offline registry keeps only:

| File | Role |
|---|---|
| `../../hosts/host-web-01.json` | Web / Nginx demo node |
| `../../hosts/host-db-01.json` | MySQL demo node |
| Additional lab host entry | Local auth.log example |
