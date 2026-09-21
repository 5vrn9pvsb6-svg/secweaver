"""Credential helpers for the local DataAsset UI."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from tempfile import NamedTemporaryFile

from .common import CREDENTIALS_DIR, ROOT, subprocess_env

from dataasset.credential_contracts import load_credential_status_file, parse_credential_statuses


SENSITIVE_CREDENTIAL_FIELDS = {
    "access_key_secret",
    "secret_access_key",
    "password",
    "private_key",
    "token",
    "access_token",
    "api_key",
    "api_secret",
    "security_token",
    "session_token",
    "client_secret",
    "secret_key",
    "key_value",
    "app_key",
    "keytab",
}


def credential_status_path() -> Path:
    return CREDENTIALS_DIR / "credential-status.json"


def load_credential_statuses() -> dict[str, str]:
    return load_credential_status_file(credential_status_path())


def write_credential_statuses(statuses: dict[str, str]) -> None:
    # Validate before the atomic replace so UI state and runtime interpretation
    # cannot diverge after a malformed status update.
    statuses = parse_credential_statuses(statuses)
    path = credential_status_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(statuses, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def credential_runtime_status(ref: str, secret_exists: bool, statuses: dict[str, str] | None = None) -> str:
    if not secret_exists:
        return "template_only"
    return (statuses or load_credential_statuses()).get(ref, "active")


def set_credential_status(ref: str, status: str) -> str:
    if status not in {"active", "disabled"}:
        raise ValueError("凭证状态只支持 active 或 disabled")
    example_path = credential_ref_to_example_path(ref)
    secret_path = credential_ref_to_secret_path(ref)
    if not example_path.exists() and not secret_path.exists():
        raise FileNotFoundError(f"credentials 不存在：{ref}")
    if not secret_path.exists():
        raise ValueError("template_only 凭证没有加密文件，不能上线或下线")
    statuses = load_credential_statuses()
    statuses[ref] = status
    write_credential_statuses(statuses)
    return status


def relative_to_credentials(path: Path) -> str:
    return path.resolve().relative_to(CREDENTIALS_DIR.resolve()).as_posix()


def credential_ref_to_parts(ref: str) -> tuple[str, str]:
    if not ref.startswith("vault://"):
        raise ValueError("credential_id 必须使用 vault://type/name 格式")
    body = ref.removeprefix("vault://").strip("/").replace("\\", "/")
    parts = body.split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1] or any(part in ("", ".", "..") for part in body.split("/")):
        raise ValueError("credential_id 必须使用 vault://type/name 格式")
    return parts[0], parts[1]


def credential_ref_to_example_path(ref: str) -> Path:
    namespace, name = credential_ref_to_parts(ref)
    path = (CREDENTIALS_DIR / "examples" / namespace / f"{name}.yaml").resolve()
    if CREDENTIALS_DIR.resolve() not in path.parents:
        raise ValueError("credentials examples 路径越界")
    return path


def credential_ref_to_secret_path(ref: str) -> Path:
    namespace, name = credential_ref_to_parts(ref)
    path = (CREDENTIALS_DIR / "secrets" / namespace / f"{name}.enc.yaml").resolve()
    if CREDENTIALS_DIR.resolve() not in path.parents:
        raise ValueError("credentials secrets 路径越界")
    return path


def credential_ref_from_example(path: Path) -> str:
    rel = path.resolve().relative_to((CREDENTIALS_DIR / "examples").resolve())
    return "vault://" + rel.with_suffix("").as_posix()


def credential_ref_from_secret(path: Path) -> str:
    rel = path.resolve().relative_to((CREDENTIALS_DIR / "secrets").resolve())
    name = rel.as_posix()
    if name.endswith(".enc.yaml"):
        name = name[: -len(".enc.yaml")]
    elif name.endswith(".enc.yml"):
        name = name[: -len(".enc.yml")]
    return "vault://" + name


def yaml_type_from_text(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("type:"):
            return stripped.split(":", 1)[1].strip().strip('"\'') or "unknown"
    return "unknown"


def yaml_type_from_path(path: Path) -> str:
    if not path.exists():
        return "unknown"
    try:
        return yaml_type_from_text(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        return "unknown"


def list_credential_objects() -> list[dict]:
    refs: dict[str, dict[str, Path]] = {}
    examples_dir = CREDENTIALS_DIR / "examples"
    secrets_dir = CREDENTIALS_DIR / "secrets"
    if examples_dir.exists():
        for path in sorted([*examples_dir.rglob("*.yaml"), *examples_dir.rglob("*.yml")]):
            refs.setdefault(credential_ref_from_example(path), {})["example"] = path
    if secrets_dir.exists():
        for path in sorted([*secrets_dir.rglob("*.enc.yaml"), *secrets_dir.rglob("*.enc.yml")]):
            refs.setdefault(credential_ref_from_secret(path), {})["secret"] = path

    statuses = load_credential_statuses()
    items: list[dict] = []
    for ref, paths in sorted(refs.items()):
        example_path = paths.get("example")
        secret_path = paths.get("secret")
        source_path = example_path or secret_path
        namespace, name = credential_ref_to_parts(ref)
        items.append(
            {
                "file": relative_to_credentials(secret_path or example_path),
                "id": ref,
                "name": name,
                "type": yaml_type_from_path(source_path) if source_path else "unknown",
                "status": credential_runtime_status(ref, bool(secret_path), statuses),
                "environment": namespace,
                "example_file": relative_to_credentials(example_path) if example_path else "",
                "secret_file": relative_to_credentials(secret_path) if secret_path else "",
            }
        )
    return items


def load_credential_detail(object_id: str) -> tuple[dict, str]:
    example_path = credential_ref_to_example_path(object_id)
    secret_path = credential_ref_to_secret_path(object_id)
    if not example_path.exists() and not secret_path.exists():
        raise FileNotFoundError(f"credentials 不存在：{object_id}")
    content = example_path.read_text(encoding="utf-8") if example_path.exists() else secret_path.read_text(encoding="utf-8")
    namespace, name = credential_ref_to_parts(object_id)
    return {
        "credential_id": object_id,
        "name": name,
        "credential_type": yaml_type_from_text(content),
        "status": credential_runtime_status(object_id, secret_path.exists()),
        "namespace": namespace,
        "example_file": relative_to_credentials(example_path) if example_path.exists() else "",
        "secret_file": relative_to_credentials(secret_path) if secret_path.exists() else "",
        "content": content,
    }, object_id


def encrypt_credential(ref: str, example_path: Path) -> None:
    script = ROOT / "src" / "dataasset" / "credentials" / "sops-vault.sh"
    result = subprocess.run(
        [str(script), "encrypt", ref, str(example_path)],
        cwd=CREDENTIALS_DIR,
        env=subprocess_env(),
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "凭证加密失败").strip()
        raise RuntimeError(detail)


def redact_credential_content(content: str) -> str:
    lines = content.rstrip().splitlines()
    redacted: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.lstrip()
        indent = line[: len(line) - len(stripped)]
        key, separator, value = stripped.partition(":")
        if separator and key in SENSITIVE_CREDENTIAL_FIELDS:
            redacted.append(f'{indent}{key}: "REPLACE_ME"')
            index += 1
            if value.strip() in {"|", ">"}:
                while index < len(lines) and lines[index].startswith(indent + " "):
                    index += 1
            continue
        redacted.append(line)
        index += 1
    return "\n".join(redacted) + "\n"


def save_credential(payload: dict) -> tuple[Path, str]:
    ref = str(payload.get("credential_id") or "").strip()
    if not ref:
        raise ValueError("credential_id 不能为空，格式如 vault://db/ai-readonly")
    example_path = credential_ref_to_example_path(ref)
    secret_path = credential_ref_to_secret_path(ref)
    content = str(payload.get("content") or "")
    if not yaml_type_from_text(content) or yaml_type_from_text(content) == "unknown":
        raise ValueError("credentials YAML 必须包含 type 字段")
    CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
    example_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix=".credential-",
            suffix=".yaml",
            dir=CREDENTIALS_DIR,
            delete=False,
        ) as temporary:
            temporary.write(content.rstrip() + "\n")
            temporary_path = Path(temporary.name)
        encrypt_credential(ref, temporary_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    if not secret_path.exists():
        raise RuntimeError(f"SOPS 未生成加密文件：{secret_path}")
    example_path.write_text(redact_credential_content(content), encoding="utf-8")
    return secret_path, ref


def delete_credential(object_id: str) -> Path:
    example_path = credential_ref_to_example_path(object_id)
    secret_path = credential_ref_to_secret_path(object_id)
    deleted = secret_path if secret_path.exists() else example_path
    if not example_path.exists() and not secret_path.exists():
        raise FileNotFoundError(f"credentials 不存在：{object_id}")
    if example_path.exists():
        example_path.unlink()
    if secret_path.exists():
        secret_path.unlink()
    statuses = load_credential_statuses()
    if object_id in statuses:
        del statuses[object_id]
        write_credential_statuses(statuses)
    return deleted
