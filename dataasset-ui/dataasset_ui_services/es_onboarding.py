"""Customer-managed Elasticsearch onboarding service."""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from .common import DATAASSET_DIR, ROOT
from .credentials import (
    credential_ref_to_example_path,
    credential_ref_to_secret_path,
    delete_credential,
    save_credential,
)
from .onboarding import run_onboarding_apply

SRC_DATAASSET = ROOT / "src" / "dataasset"
if str(SRC_DATAASSET) not in sys.path:
    sys.path.insert(0, str(SRC_DATAASSET))

from es_onboarding import build_es_onboarding_config, discover_elasticsearch  # noqa: E402
from vault import resolve_credentials  # noqa: E402


def _inline_credentials(payload: dict[str, Any]) -> dict[str, Any]:
    auth = payload.get("credentials") or {}
    if not isinstance(auth, dict):
        raise ValueError("credentials must be an object")
    return {
        "type": "es",
        "username": str(auth.get("username") or ""),
        "password": str(auth.get("password") or ""),
        "api_key": str(auth.get("api_key") or ""),
    }


def _resolved_credentials(payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
    credential_ref = str(payload.get("credential_ref") or "").strip()
    if credential_ref:
        return resolve_credentials(credential_ref), credential_ref
    inline = _inline_credentials(payload)
    if inline.get("username") or inline.get("api_key"):
        return inline, credential_ref
    return {}, ""


def probe_customer_es(payload: dict[str, Any]) -> dict[str, Any]:
    """Use the same explicit TLS policy for discovery and generated connectors."""
    endpoint = str(payload.get("endpoint") or "").strip()
    if not endpoint:
        raise ValueError("endpoint is required")
    credentials, _ = _resolved_credentials(payload)
    return discover_elasticsearch(
        endpoint,
        credentials,
        index=str(payload.get("index") or ""),
        ca_file=str(payload.get("ca_file") or ""),
        tls_verify=payload.get("tls_verify", True),
        dataasset_root=DATAASSET_DIR,
        timeout=int(payload.get("timeout") or 15),
    )


def _default_ref(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "customer-es"
    return f"vault://es/{slug}-readonly"


def _credential_yaml(credentials: dict[str, Any]) -> str:
    lines = ["type: es"]
    for key in ("username", "password", "api_key"):
        value = str(credentials.get(key) or "")
        if value:
            lines.append(f"{key}: {json.dumps(value, ensure_ascii=False)}")
    return "\n".join(lines) + "\n"


def apply_customer_es(payload: dict[str, Any]) -> dict[str, Any]:
    index = str(payload.get("index") or "").strip()
    if not index:
        raise ValueError("select or enter an index pattern before applying")
    probe = probe_customer_es(payload)
    credentials, credential_ref = _resolved_credentials(payload)
    created_credential = False
    if not credential_ref:
        if not (credentials.get("username") or credentials.get("api_key")):
            raise ValueError("select an existing credential or enter Basic/API Key credentials")
        credential_ref = _default_ref(str(payload.get("name") or "customer-es"))

    normalized = dict(payload)
    normalized["output_dir"] = str(DATAASSET_DIR)
    config = build_es_onboarding_config(normalized, probe, credential_ref)
    preview = run_onboarding_apply(config, dry_run=True, force=bool(payload.get("force")))
    if not preview.get("ok"):
        return {"ok": False, "stage": "preview", "probe": probe, "credential_ref": credential_ref, "created_credential": False, "result": preview}
    if not str(payload.get("credential_ref") or "").strip():
        if credential_ref_to_secret_path(credential_ref).exists() or credential_ref_to_example_path(credential_ref).exists():
            raise ValueError(f"credential {credential_ref} already exists; select it from the existing credential list")
        save_credential({"credential_id": credential_ref, "content": _credential_yaml(credentials)})
        created_credential = True
    applied = run_onboarding_apply(config, dry_run=False, force=bool(payload.get("force")))
    if not applied.get("ok") and created_credential:
        delete_credential(credential_ref)
        created_credential = False
    return {
        "ok": bool(applied.get("ok")),
        "stage": "active" if applied.get("ok") else "apply",
        "probe": probe,
        "credential_ref": credential_ref,
        "created_credential": created_credential,
        "config": config,
        "result": applied,
    }
