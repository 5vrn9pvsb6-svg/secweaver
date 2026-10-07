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

# printf preserves shell-escaped command hints; macOS echo may interpret their
# backslashes and corrupt multibyte paths before the UI decodes UTF-8 errors.
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
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

# Saving never initializes or rotates a Vault. A harmless native SOPS round-trip
# checks the exact target rule and key availability without parsing YAML ourselves,
# opening real credentials, or writing a probe into the Vault. External age keys,
# GPG and KMS remain usable through the same SOPS environment as encryption.
cmd_check() {
  local ref="${1:-}"
  [[ -n "$ref" ]] || die "用法: check <vault://namespace/name>"
  local rel_override sops_bin init_hint python_bin reason="" probe encrypted
  rel_override="secrets/$(ref_to_rel "$ref")"
  if [[ ! -f "$SOPS_CONFIG" || ! -r "$SOPS_CONFIG" ]]; then
    reason="Vault 未初始化或配置不可读：缺少可读取的 credentials/.sops.yaml。"
  elif grep -Fq 'REPLACE_WITH_YOUR_AGE_PUBLIC_KEY' "$SOPS_CONFIG"; then
    reason="Vault 未初始化：credentials/.sops.yaml 仍使用占位公钥。"
  fi
  if [[ -n "$reason" ]]; then
    # Bash 3's %q can corrupt UTF-8 paths on macOS. Use Python's standard shell
    # quoting when available; fallback instructions require the same asset root.
    init_hint="在仓库根目录、相同 DATAASSET_ROOT 下运行 bash src/dataasset/credentials/sops-vault.sh init"
    python_bin="$(resolve_tool python3 || true)"
    if [[ -n "$python_bin" ]]; then
      init_hint="$("$python_bin" -c 'import shlex, sys; print("DATAASSET_ROOT=" + shlex.quote(sys.argv[1]) + " bash " + shlex.quote(sys.argv[2]) + " init")' "$DATAASSET_ROOT" "$REPO_ROOT/src/dataasset/credentials/sops-vault.sh")"
    fi
    die "${reason}仅对空 Vault 执行：${init_hint}；已有密文时请恢复原策略和私钥，不要重新初始化。"
  fi
  sops_bin="$(resolve_tool sops)" || die "Vault 检查失败：未找到可执行的 SOPS。安装 sops，或为 UI 设置 SOPS_BIN=/absolute/path/to/sops；检查后再保存。"
  export_sops_env
  probe='{"access_key_secret":"secweaver-vault-preflight","password":"secweaver-vault-preflight","token":"secweaver-vault-preflight"}'
  # Keep diagnostic output generic: malformed policies may contain sensitive text.
  # SOPS remains the authority for YAML, rule selection and cryptographic validity.
  if ! encrypted="$(printf '%s' "$probe" | "$sops_bin" --config "$SOPS_CONFIG" --encrypt \
      --filename-override "$rel_override" --input-type json --output-type json /dev/stdin 2>/dev/null)"; then
    die "Vault 策略不可用：SOPS 无法对当前凭证路径加密。请检查 credentials/.sops.yaml 的 creation_rules、公钥/接收者和密钥服务权限；不会自动修改策略。"
  fi
  if ! printf '%s' "$encrypted" | "$sops_bin" --decrypt --input-type json --output-type json /dev/stdin >/dev/null 2>&1; then
    die "Vault 密钥不可用：探针已加密但无法解密。请恢复与策略匹配的 credentials/.age/key.txt，或检查 SOPS_AGE_KEY_FILE、外部密钥和密钥服务权限；不要重新生成密钥或覆盖已有策略。"
  fi
  info "Vault 检查通过：策略和密钥可用，未修改任何凭证"
}

cmd_init() {
  # Share quickstart's locked, idempotent initializer rather than overwriting a
  # policy on every run. Python owns atomic publication and bounded crypto checks;
  # the shell facade also works with macOS's bundled Bash 3.2.
  local python_bin
  python_bin="$(resolve_tool python3)" || die "Vault 初始化需要 Python 3.10+；请先运行 make setup"
  "$python_bin" "$REPO_ROOT/src/dataasset/credentials/init_vault.py" "$@"
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
  init [--check-ref vault://...] 安全初始化空 Vault；已有策略/密钥只检查、不覆盖
  check  vault://sls/security-readonly   只读检查策略和密钥，不初始化或修改凭证
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
    init) cmd_init "$@" ;;
    check) cmd_check "$@" ;;
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
