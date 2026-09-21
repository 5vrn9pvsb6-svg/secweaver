#!/usr/bin/env bash
# 本地 SOPS Vault：管理 vault:// 引用对应的加密文件
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DATAASSET_ROOT="${DATAASSET_ROOT:-$REPO_ROOT/dataasset}"
if [[ "$DATAASSET_ROOT" != /* ]]; then
  DATAASSET_ROOT="$REPO_ROOT/$DATAASSET_ROOT"
fi
export DATAASSET_ROOT
ROOT="$DATAASSET_ROOT/credentials"
RESOLVE_SCRIPT="$REPO_ROOT/src/dataasset/credentials/resolve.py"
SECRETS_DIR="$ROOT/secrets"
EXAMPLES_DIR="$ROOT/examples"
AGE_DIR="$ROOT/.age"
AGE_KEY="$AGE_DIR/key.txt"
SOPS_CONFIG="$ROOT/.sops.yaml"

die() { echo "error: $*" >&2; exit 1; }
info() { echo "→ $*"; }

resolve_tool() {
  local name="$1"
  local override=""
  case "$name" in
    sops) override="${SOPS_BIN:-}" ;;
    age) override="${AGE_BIN:-}" ;;
    age-keygen) override="${AGE_KEYGEN_BIN:-}" ;;
  esac

  if [[ -n "$override" && -x "$override" ]]; then
    printf '%s\n' "$override"
    return 0
  fi
  if [[ -n "$override" ]]; then
    return 1
  fi
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return 0
  fi

  local candidate
  for candidate in \
    "/opt/homebrew/bin/$name" \
    "/usr/local/bin/$name" \
    "/opt/local/bin/$name" \
    "$HOME/.local/bin/$name" \
    "$HOME/bin/$name"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

need_cmd() {
  local env_name="${1^^}_BIN"
  case "$1" in
    sops) env_name="SOPS_BIN" ;;
    age) env_name="AGE_BIN" ;;
    age-keygen) env_name="AGE_KEYGEN_BIN" ;;
  esac
  resolve_tool "$1" >/dev/null || die "未找到 $1。已检查 PATH、Homebrew 和用户级目录；可设置 ${env_name}。安装: brew install sops age"
}

ref_to_rel() {
  local ref="$1"
  [[ "$ref" =~ ^vault://([^/]+)/(.+)$ ]] || die "无效 ref: $ref（格式 vault://name/path）"
  echo "${BASH_REMATCH[1]}/${BASH_REMATCH[2]}.enc.yaml"
}

ref_to_example() {
  local ref="$1"
  [[ "$ref" =~ ^vault://([^/]+)/(.+)$ ]] || die "无效 ref: $ref"
  echo "${BASH_REMATCH[1]}/${BASH_REMATCH[2]}.yaml"
}

secret_path() {
  echo "$SECRETS_DIR/$(ref_to_rel "$1")"
}

example_path() {
  echo "$EXAMPLES_DIR/$(ref_to_example "$1")"
}

export_sops_env() {
  export SOPS_CONFIG="$SOPS_CONFIG"
  if [[ -f "$AGE_KEY" ]]; then
    export SOPS_AGE_KEY_FILE="$AGE_KEY"
  fi
}

cmd_init() {
  need_cmd sops
  need_cmd age
  need_cmd age-keygen

  local age_keygen_bin
  age_keygen_bin="$(resolve_tool age-keygen)"

  mkdir -p "$AGE_DIR" "$SECRETS_DIR"
  if [[ ! -f "$AGE_KEY" ]]; then
    info "生成 age 私钥 → $AGE_KEY"
    "$age_keygen_bin" -o "$AGE_KEY" >/dev/null
    chmod 600 "$AGE_KEY"
  fi

  local pubkey
  pubkey="$(grep '^# public key:' "$AGE_KEY" | cut -d: -f2- | xargs)"
  [[ -n "$pubkey" ]] || die "无法从 $AGE_KEY 读取公钥"

  cat > "$SOPS_CONFIG" <<EOF
creation_rules:
  - path_regex: secrets/.*\\.enc\\.yaml\$
    encrypted_regex: '^(access_key_secret|secret_access_key|password|private_key|token|access_token|api_key|api_secret|security_token|session_token|client_secret|secret_key|key_value|app_key|keytab)\$'
    age: ${pubkey}
EOF
  info "已写入 $SOPS_CONFIG"
  info "私钥仅保存在本机 $AGE_KEY，勿提交 Git"
  echo
  echo "下一步:"
  echo "  src/dataasset/credentials/sops-vault.sh bootstrap   # 从 examples 生成全部加密文件"
  echo "  src/dataasset/credentials/sops-vault.sh edit vault://sls/security-readonly"
}

cmd_bootstrap() {
  [[ -f "$SOPS_CONFIG" ]] || die "请先运行: src/dataasset/credentials/sops-vault.sh init"
  export_sops_env

  local example ref
  while IFS= read -r -d '' example; do
    local rel="${example#"$EXAMPLES_DIR"/}"
    local base="${rel%.yaml}"
    ref="vault://${base}"
    cmd_encrypt "$ref" "$example"
  done < <(find "$EXAMPLES_DIR" -name '*.yaml' -type f -print0)
  info "bootstrap 完成"
}

cmd_encrypt() {
  local ref="${1:-}"
  local from="${2:-}"
  [[ -n "$ref" ]] || die "用法: encrypt <vault://name/path> [source.yaml]"
  export_sops_env

  local dest example rel_override tmp sops_bin
  sops_bin="$(resolve_tool sops)" || die "未找到 sops。可设置 SOPS_BIN=/absolute/path/to/sops"
  dest="$(secret_path "$ref")"
  example="${from:-$(example_path "$ref")}"
  [[ -f "$example" ]] || die "示例不存在: $example"

  rel_override="secrets/$(ref_to_rel "$ref")"
  mkdir -p "$(dirname "$dest")"
  info "加密 $example → $dest"
  tmp="$(mktemp "${dest}.tmp.XXXXXX")"
  if ! "$sops_bin" --encrypt \
      --filename-override "$rel_override" \
      --input-type yaml \
      --output-type yaml \
      "$example" > "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  mv "$tmp" "$dest"
}

cmd_edit() {
  local ref="${1:-}"
  [[ -n "$ref" ]] || die "用法: edit <vault://name/path>"
  [[ -f "$SOPS_CONFIG" ]] || die "请先运行: src/dataasset/credentials/sops-vault.sh init"
  export_sops_env

  local dest example sops_bin
  sops_bin="$(resolve_tool sops)" || die "未找到 sops。可设置 SOPS_BIN=/absolute/path/to/sops"
  dest="$(secret_path "$ref")"
  if [[ ! -f "$dest" ]]; then
    example="$(example_path "$ref")"
    [[ -f "$example" ]] || die "无加密文件且无示例: $ref"
    cmd_encrypt "$ref" "$example"
  fi
  exec "$sops_bin" "$dest"
}

cmd_get() {
  local ref="${1:-}"
  local show="${2:-}"
  [[ -n "$ref" ]] || die "用法: get <vault://name/path> [--show-secrets]"
  export_sops_env

  local dest sops_bin
  sops_bin="$(resolve_tool sops)" || die "未找到 sops。可设置 SOPS_BIN=/absolute/path/to/sops"
  dest="$(secret_path "$ref")"
  [[ -f "$dest" ]] || die "未找到: ${dest}（先 edit 或 bootstrap）"

  if [[ "$show" == "--show-secrets" ]]; then
    "$sops_bin" -d --output-type yaml "$dest"
  else
    python3 "$RESOLVE_SCRIPT" "$ref" --mask
  fi
}

cmd_list() {
  [[ -d "$SECRETS_DIR" ]] || { echo "(无 secrets/ 目录，先 init + bootstrap)"; return 0; }
  find "$SECRETS_DIR" -name '*.enc.yaml' -type f | sort | while read -r f; do
    local rel="${f#"$SECRETS_DIR"/}"
    local path="${rel%.enc.yaml}"
    echo "vault://${path}"
  done
}

cmd_resolve() {
  local ref="${1:-}"
  [[ -n "$ref" ]] || die "用法: resolve <vault://name/path>"
  export_sops_env
  python3 "$RESOLVE_SCRIPT" "$ref"
}

usage() {
  cat <<'EOF'
本地 SOPS Vault — 对应 connectors 中的 credentials_ref

命令:
  init                          生成 age 密钥与 .sops.yaml
  bootstrap                     从 examples/ 加密生成全部 secrets/*.enc.yaml
  edit   vault://sls/security-readonly   编辑（不存在则从 example 创建）
  get    vault://sls/security-readonly   查看（默认脱敏）
  get    vault://... --show-secrets      查看明文（仅本地调试）
  list                          列出已有 ref
  resolve vault://...           输出 JSON（供平台/Data Access Layer 调用）

依赖: brew install sops age

映射规则:
  vault://sls/security-readonly → secrets/sls/security-readonly.enc.yaml
EOF
}

main() {
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    init) cmd_init ;;
    bootstrap) cmd_bootstrap ;;
    encrypt) cmd_encrypt "$@" ;;
    edit) cmd_edit "$@" ;;
    get) cmd_get "$@" ;;
    list) cmd_list ;;
    resolve) cmd_resolve "$@" ;;
    -h|--help|help|"") usage ;;
    *) die "未知命令: $cmd（--help 查看用法）" ;;
  esac
}

main "$@"
