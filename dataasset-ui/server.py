#!/usr/bin/env python3
"""Local DataAsset UI server.

This HTTP layer intentionally stays small: domain logic lives in
`dataasset_ui_services/*` so contributors can work on onboarding, credentials,
validation, and topology without editing one large route file.
"""

from __future__ import annotations

import json
import mimetypes
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

UI_PACKAGE_DIR = Path(__file__).resolve().parent
if str(UI_PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(UI_PACKAGE_DIR))

from dataasset_ui_services.asset_actions import run_asset_action
from dataasset_ui_services.common import (
    ASSETS_DIR,
    HOSTS_DIR,
    ROOT,
    UI_DIR,
    read_json,
    rel_to_root,
    safe_child,
    validation_python,
)
from dataasset_ui_services.credentials import list_credential_objects, set_credential_status
from dataasset_ui_services.es_onboarding import apply_customer_es, probe_customer_es
from dataasset_ui_services.objects import delete_object, load_detail, save_object
from dataasset_ui_services.onboarding import (
    clear_connector_catalog_cache,
    clear_connector_registry_cache,
    connector_capability_catalog,
    load_onboarding_meta,
    registry_connector_types,
    run_onboarding_apply,
)
from dataasset_ui_services.portable import portable_action, portable_status
from dataasset_ui_services.registry import load_registry
from dataasset_ui_services.reports import read_reports, run_demo_all
from dataasset_ui_services.topology import build_topology
from dataasset_ui_services.validation import run_validation, validation_advice


def refresh_connector_metadata() -> None:
    clear_connector_registry_cache()
    clear_connector_catalog_cache()


class Handler(BaseHTTPRequestHandler):
    server_version = "DataAssetUI/0.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - BaseHTTPRequestHandler API
        sys.stderr.write("[dataasset-ui] " + format % args + "\n")

    def send_json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, message: str, status: int = 400) -> None:
        self.send_json({"ok": False, "error": message}, status)

    def read_body_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        return json.loads(raw or "{}")

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        try:
            if path == "/api/registry":
                self.send_json({"ok": True, "data": load_registry()})
                return
            if path == "/api/topology":
                self.send_json({"ok": True, "data": build_topology()})
                return
            if path == "/api/reports":
                self.send_json({"ok": True, "data": read_reports()})
                return
            if path == "/api/onboarding/meta":
                if query.get("refresh", ["0"])[0] in {"1", "true", "yes"}:
                    refresh_connector_metadata()
                self.send_json({"ok": True, "data": load_onboarding_meta()})
                return
            if path == "/api/connectors/catalog":
                self.send_json({"ok": True, "data": connector_capability_catalog()})
                return
            if path == "/api/portable/status":
                self.send_json(portable_status())
                return
            if path == "/api/detail":
                kind = query.get("kind", [""])[0]
                object_id = query.get("id", [""])[0]
                data, filename = load_detail(kind, object_id)
                self.send_json({"ok": True, "kind": kind, "id": object_id, "data": data, "file": filename})
                return
            if path == "/api/asset":
                asset_id = query.get("id", [""])[0]
                asset_path = safe_child(ASSETS_DIR, asset_id)
                if not asset_path.exists():
                    self.send_error_json(f"资产不存在：{asset_id}", HTTPStatus.NOT_FOUND)
                    return
                self.send_json({"ok": True, "data": read_json(asset_path), "file": asset_path.name})
                return
            if path == "/api/host":
                host_id = query.get("id", [""])[0]
                host_path = safe_child(HOSTS_DIR, host_id)
                if not host_path.exists():
                    self.send_error_json(f"主机不存在：{host_id}", HTTPStatus.NOT_FOUND)
                    return
                self.send_json({"ok": True, "data": read_json(host_path), "file": host_path.name})
                return
            self.serve_static(path)
        except Exception as exc:  # noqa: BLE001 - API boundary
            self.send_error_json(str(exc), HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/demo/all":
                result = run_demo_all()
                output = (result.stdout or "") + (result.stderr or "")
                self.send_json(
                    {
                        "ok": result.returncode == 0,
                        "returncode": result.returncode,
                        "python": validation_python(),
                        "output": output,
                        "reports": read_reports(),
                    }
                )
                return
            if parsed.path == "/api/connectors/reload":
                refresh_connector_metadata()
                self.send_json(
                    {
                        "ok": True,
                        "data": {
                            "connector_types": registry_connector_types(),
                            "connector_catalog": connector_capability_catalog(),
                        },
                    }
                )
                return
            if parsed.path == "/api/asset/action":
                request_payload = self.read_body_json()
                asset_id = str(request_payload.get("asset_id") or "").strip()
                action = str(request_payload.get("action") or "").strip()
                if not asset_id:
                    self.send_error_json("asset_id 不能为空")
                    return
                self.send_json(run_asset_action(asset_id, action))
                return
            if parsed.path == "/api/credential/status":
                request_payload = self.read_body_json()
                credential_id = str(request_payload.get("credential_id") or "").strip()
                status = str(request_payload.get("status") or "").strip()
                if not credential_id:
                    self.send_error_json("credential_id 不能为空")
                    return
                self.send_json({"ok": True, "id": credential_id, "status": set_credential_status(credential_id, status)})
                return
            if parsed.path == "/api/onboarding/preview":
                request_payload = self.read_body_json()
                config = request_payload.get("config")
                if not isinstance(config, dict):
                    self.send_error_json("缺少 config 对象")
                    return
                self.send_json(run_onboarding_apply(config, dry_run=True))
                return
            if parsed.path == "/api/es/onboarding/probe":
                self.send_json(probe_customer_es(self.read_body_json()))
                return
            if parsed.path == "/api/es/onboarding/apply":
                self.send_json(apply_customer_es(self.read_body_json()))
                return
            if parsed.path == "/api/onboarding/apply":
                request_payload = self.read_body_json()
                config = request_payload.get("config")
                if not isinstance(config, dict):
                    self.send_error_json("缺少 config 对象")
                    return
                force = bool(request_payload.get("force", False))
                self.send_json(run_onboarding_apply(config, dry_run=False, force=force))
                return
            if parsed.path == "/api/portable/action":
                request_payload = self.read_body_json()
                action = str(request_payload.get("action") or "").strip()
                payload = request_payload.get("payload") or {}
                if not isinstance(payload, dict):
                    self.send_error_json("payload must be an object")
                    return
                self.send_json(portable_action(action, payload))
                return
            if parsed.path == "/api/object":
                request_payload = self.read_body_json()
                kind = str(request_payload.get("kind") or "").strip()
                data = request_payload.get("data")
                if not isinstance(data, dict):
                    self.send_error_json("缺少 data 对象")
                    return
                original_id = str(request_payload.get("original_id") or "").strip()
                path, object_id = save_object(kind, data, original_id=original_id)
                self.send_json({"ok": True, "kind": kind, "id": object_id, "file": rel_to_root(path)})
                return
            if parsed.path == "/api/asset":
                payload = self.read_body_json()
                asset = payload.get("asset")
                if not isinstance(asset, dict):
                    self.send_error_json("缺少 asset 对象")
                    return
                asset_id = str(asset.get("asset_id") or "").strip()
                if not asset_id:
                    self.send_error_json("asset_id 不能为空")
                    return
                path, _ = save_object("asset", asset)
                self.send_json({"ok": True, "file": rel_to_root(path)})
                return
            if parsed.path == "/api/host":
                payload = self.read_body_json()
                host = payload.get("host")
                if not isinstance(host, dict):
                    self.send_error_json("缺少 host 对象")
                    return
                host_id = str(host.get("host_id") or "").strip()
                if not host_id:
                    self.send_error_json("host_id 不能为空")
                    return
                path, _ = save_object("host", host)
                self.send_json({"ok": True, "file": rel_to_root(path)})
                return
            if parsed.path == "/api/validate":
                request_payload = self.read_body_json()
                requested_bundle_ids = request_payload.get("bundle_ids", [])
                if not isinstance(requested_bundle_ids, list):
                    requested_bundle_ids = []
                self.send_json(
                    run_validation(
                        sync_catalog=bool(request_payload.get("sync_catalog", False)),
                        strict=bool(request_payload.get("strict", False)),
                        only_active=bool(request_payload.get("only_active", False)),
                        runtime_ready=bool(request_payload.get("runtime_ready", False)),
                        bundle_ids=[
                            str(bundle_id)
                            for bundle_id in requested_bundle_ids
                            if str(bundle_id).strip()
                        ],
                    )
                )
                return
            self.send_error_json("未知 API", HTTPStatus.NOT_FOUND)
        except TimeoutError as exc:
            self.send_error_json(str(exc), HTTPStatus.REQUEST_TIMEOUT)
        except ValueError as exc:
            self.send_error_json(str(exc), HTTPStatus.BAD_REQUEST)
        except Exception as exc:  # noqa: BLE001 - API boundary
            self.send_error_json(str(exc), HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        try:
            if parsed.path == "/api/object":
                kind = query.get("kind", [""])[0]
                object_id = query.get("id", [""])[0]
                deleted_path = delete_object(kind, object_id)
                self.send_json({"ok": True, "deleted": rel_to_root(deleted_path)})
                return
            if parsed.path == "/api/host":
                host_id = query.get("id", [""])[0]
                deleted_path = delete_object("host", host_id)
                self.send_json({"ok": True, "deleted": rel_to_root(deleted_path)})
                return
            self.send_error_json("未知 API", HTTPStatus.NOT_FOUND)
        except FileNotFoundError as exc:
            self.send_error_json(str(exc), HTTPStatus.NOT_FOUND)
        except Exception as exc:  # noqa: BLE001 - API boundary
            self.send_error_json(str(exc), HTTPStatus.INTERNAL_SERVER_ERROR)

    def serve_static(self, path: str) -> None:
        if path in {"", "/"}:
            path = "/index.html"
        relative = path.lstrip("/")
        target = (UI_DIR / relative).resolve()
        if UI_DIR.resolve() not in target.parents and target != UI_DIR.resolve():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not target.exists() or not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        body = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    host = "127.0.0.1"
    port = int(os.environ.get("DATAASSET_UI_PORT", "8765"))
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"DataAsset UI running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
