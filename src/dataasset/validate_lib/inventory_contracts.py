"""Host and network semantic checks used by the DataAsset validator."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from .diagnostics import Report


def parse_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _parse_network(value: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        # Inventory CIDRs describe a network even when operators enter a host
        # address, so normalize host bits instead of rejecting the whole record.
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def _is_hostname_like(value: Any) -> bool:
    return isinstance(value, str) and bool(re.search(r"[a-zA-Z]", value))


def check_network_contract(report: Report, path: Path, data: dict[str, Any]) -> None:
    """Check CIDR and gateway consistency after JSON Schema validation."""
    network = _parse_network(data.get("cidr"))
    if network is None:
        report.error(
            f"{path}: network.cidr={data.get('cidr')!r} 不是合法 CIDR",
            code="network-invalid-cidr",
            object_type="network",
            object_id=str(data.get("network_id") or ""),
            path=path,
            field="cidr",
            suggested_fix="将 cidr 修正为合法 IPv4/IPv6 CIDR，例如 10.0.1.0/24。",
        )
    gateway_ip = parse_ip(data.get("gateway_ip"))
    if gateway_ip is not None and network is not None and gateway_ip not in network:
        report.warn(
            f"{path}: gateway_ip={data.get('gateway_ip')!r} 不在 cidr={data.get('cidr')!r} 内",
            code="network-gateway-out-of-cidr",
            object_type="network",
            object_id=str(data.get("network_id") or ""),
            path=path,
            field="gateway_ip",
            suggested_fix="确认网关 IP 与 CIDR 是否属于同一网段；若是跨网关/云路由，请在 description 说明。",
        )


def _check_ip_in_network(
    report: Report,
    *,
    path: Path,
    host_id: str,
    ip_value: Any,
    network_id: str,
    network: dict[str, Any],
    field: str,
) -> None:
    ip_obj = parse_ip(ip_value)
    if ip_obj is None:
        if ip_value and not _is_hostname_like(ip_value):
            report.warn(
                f"{path}: {field}={ip_value!r} 不是可解析 IP，无法校验是否属于 network_id={network_id!r}",
                code="host-ip-not-parseable",
                object_type="host",
                object_id=host_id,
                path=path,
                field=field,
                suggested_fix="若字段表示主机 IP，请填真实 IP；若是域名，请补 interfaces[].ip 绑定真实内网地址。",
            )
        return
    net_obj = _parse_network(network.get("cidr"))
    if net_obj is not None and ip_obj not in net_obj:
        report.warn(
            f"{path}: {field}={ip_value!r} 不在 network_id={network_id!r} cidr={network.get('cidr')!r} 内",
            code="host-ip-out-of-network",
            object_type="host",
            object_id=host_id,
            path=path,
            field=field,
            suggested_fix="修正 host.network_id / interfaces[].network_id，或将 IP 归入正确 network。",
        )


def check_host_contract(
    report: Report,
    path: Path,
    data: dict[str, Any],
    networks: dict[str, tuple[Path, dict[str, Any]]] | None = None,
) -> None:
    """Check host-to-network references and the normalized exposure surface."""
    host_id = str(data.get("host_id") or "")
    networks = networks or {}
    network_id = data.get("network_id")
    if network_id:
        if network_id not in networks:
            report.error(
                f"{path}: network_id 引用未知网络 {network_id!r}",
                code="host-unknown-network",
                object_type="host",
                object_id=host_id,
                path=path,
                field="network_id",
                suggested_fix="在 dataasset/networks/net-*.json 注册对应 network，或修正 host.network_id。",
            )
        else:
            _, network = networks[network_id]
            _check_ip_in_network(
                report,
                path=path,
                host_id=host_id,
                ip_value=data.get("host_ip"),
                network_id=str(network_id),
                network=network,
                field="host_ip",
            )

    for idx, interface in enumerate(data.get("interfaces") or []):
        if not isinstance(interface, dict):
            report.error(f"{path}: interfaces[{idx}] 必须为 object")
            continue
        iface_network_id = interface.get("network_id") or network_id
        if iface_network_id and iface_network_id not in networks:
            report.error(
                f"{path}: interfaces[{idx}].network_id 引用未知网络 {iface_network_id!r}",
                code="host-interface-unknown-network",
                object_type="host",
                object_id=host_id,
                path=path,
                field=f"interfaces[{idx}].network_id",
                suggested_fix="在 networks/ 注册该网段，或修正接口 network_id。",
            )
            continue
        if iface_network_id:
            _check_ip_in_network(
                report,
                path=path,
                host_id=host_id,
                ip_value=interface.get("ip"),
                network_id=str(iface_network_id),
                network=networks[iface_network_id][1],
                field=f"interfaces[{idx}].ip",
            )

    exposure = data.get("exposure") or {}
    if not isinstance(exposure, dict):
        return
    if exposure.get("internet_exposed") is True and not exposure.get("internet_ip"):
        report.warn(
            f"{path}: exposure.internet_exposed=true 但未填写 exposure.internet_ip",
            code="host-missing-internet-ip",
            object_type="host",
            object_id=host_id,
            path=path,
            field="exposure.internet_ip",
            suggested_fix='按 exposure 格式补充公网 IP / EIP，例如 internet_ip: "1.2.3.4"。',
        )
    for idx, item in enumerate(exposure.get("exposed_ports") or []):
        if isinstance(item, int):
            port = item
            field = f"exposure.exposed_ports[{idx}]"
        elif isinstance(item, dict):
            port = item.get("port")
            field = f"exposure.exposed_ports[{idx}].port"
        else:
            port = None
            field = f"exposure.exposed_ports[{idx}]"
        if not isinstance(port, int) or port < 1 or port > 65535:
            report.error(
                f"{path}: {field} 必须是 1-65535 整数，或包含 port 字段的对象",
                code="host-invalid-exposed-port",
                object_type="host",
                object_id=host_id,
                path=path,
                field=field,
                suggested_fix='推荐格式为 exposure.exposed_ports: [443, 80, 10081]；如需服务详情，可使用 {"port": 443, "protocol": "tcp"}。',
            )
