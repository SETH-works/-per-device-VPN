"""Strict TOML loader for the versioned declarative policy plan."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from .model import Device, Exit, ExitProtocol, FailureAction, Plan, Policy


class PlanError(ValueError):
    """A plan is malformed or violates a safety invariant."""


_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
_ROOT_KEYS = {"schema_version", "exits", "devices"}
_EXIT_KEYS = {"id", "provider", "protocol", "verified", "credential_ref"}
_DEVICE_KEYS = {"id", "policy", "exit_id", "failure_action", "identity_verified", "selector"}


def load_plan(path: str | Path) -> Plan:
    with Path(path).open("rb") as stream:
        raw = tomllib.load(stream)
    return parse_plan(raw)


def parse_plan(raw: dict[str, Any]) -> Plan:
    _keys(raw, _ROOT_KEYS, "plan")
    if raw.get("schema_version") != 1:
        raise PlanError("schema_version must be 1")
    raw_exits = raw.get("exits", [])
    raw_devices = raw.get("devices", [])
    if not isinstance(raw_exits, list) or not isinstance(raw_devices, list):
        raise PlanError("exits and devices must be arrays of tables")

    exits: list[Exit] = []
    for item in raw_exits:
        if not isinstance(item, dict):
            raise PlanError("each exit must be a table")
        _keys(item, _EXIT_KEYS, "exit")
        ident = _identifier(item.get("id"), "exit id")
        provider = _text(item.get("provider"), "provider")
        try:
            protocol = ExitProtocol(_text(item.get("protocol"), "protocol").upper())
        except ValueError as exc:
            raise PlanError("protocol must be DIRECT, WIREGUARD, or OPENVPN") from exc
        verified = item.get("verified", False)
        if not isinstance(verified, bool):
            raise PlanError(f"exit {ident}: verified must be boolean")
        credential_ref = item.get("credential_ref")
        if credential_ref is not None:
            credential_ref = _text(credential_ref, "credential_ref")
            if not credential_ref.startswith(("file:", "systemd:", "keyring:")):
                raise PlanError(f"exit {ident}: credential_ref must name a secret store, never contain a credential")
        if protocol is ExitProtocol.DIRECT and verified:
            raise PlanError("DIRECT is a routing mode, not a verified VPN exit")
        exits.append(Exit(ident, provider, protocol, verified, credential_ref))

    _unique((item.id for item in exits), "exit")
    if "DIRECT" not in {item.id for item in exits}:
        raise PlanError("an exit with id DIRECT is required")
    direct = next(item for item in exits if item.id == "DIRECT")
    if not direct.is_direct:
        raise PlanError("the DIRECT exit must use protocol DIRECT")

    devices: list[Device] = []
    for item in raw_devices:
        if not isinstance(item, dict):
            raise PlanError("each device must be a table")
        _keys(item, _DEVICE_KEYS, "device")
        ident = _identifier(item.get("id"), "device id")
        try:
            policy = Policy(_text(item.get("policy"), "policy").upper())
        except ValueError as exc:
            raise PlanError("policy must be DIRECT, SELECTED_VPN, VPN_REQUIRED, or DISABLED") from exc
        exit_id = item.get("exit_id")
        if exit_id is not None:
            exit_id = _identifier(exit_id, "exit_id")
            if exit_id not in {entry.id for entry in exits}:
                raise PlanError(f"device {ident}: unknown exit_id {exit_id}")
        failure_action = item.get("failure_action")
        if failure_action is not None:
            try:
                failure_action = FailureAction(_text(failure_action, "failure_action").upper())
            except ValueError as exc:
                raise PlanError(f"device {ident}: failure_action must be BLOCK or DIRECT") from exc
        identity_verified = item.get("identity_verified", False)
        selector = item.get("selector")
        if not isinstance(identity_verified, bool):
            raise PlanError(f"device {ident}: identity_verified must be boolean")
        if selector is not None:
            selector = _text(selector, "selector")
        if identity_verified and not selector:
            raise PlanError(f"device {ident}: verified identity requires a selector")
        if selector and not identity_verified:
            raise PlanError(f"device {ident}: selector cannot be used before identity verification")
        if policy in (Policy.SELECTED_VPN, Policy.VPN_REQUIRED):
            if not exit_id or exit_id == "DIRECT":
                raise PlanError(f"device {ident}: VPN policy requires a VPN exit_id")
            selected_exit = next(entry for entry in exits if entry.id == exit_id)
            if selected_exit.is_direct:
                raise PlanError(f"device {ident}: VPN policy cannot select DIRECT")
        elif exit_id is not None:
            raise PlanError(f"device {ident}: exit_id is only valid for a VPN policy")
        if policy is Policy.SELECTED_VPN and failure_action is None:
            raise PlanError(f"device {ident}: SELECTED_VPN requires an explicit failure_action")
        if policy is Policy.VPN_REQUIRED and failure_action not in (None, FailureAction.BLOCK):
            raise PlanError(f"device {ident}: VPN_REQUIRED always fails closed")
        if policy in (Policy.DIRECT, Policy.DISABLED) and failure_action is not None:
            raise PlanError(f"device {ident}: failure_action is only valid for a VPN policy")
        devices.append(Device(ident, policy, exit_id, failure_action, identity_verified, selector))

    _unique((item.id for item in devices), "device")
    return Plan(1, tuple(exits), tuple(devices))


def _keys(value: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise PlanError(f"{where}: unknown fields: {', '.join(sorted(unknown))}")


def _identifier(value: Any, label: str) -> str:
    text = _text(value, label)
    if not _ID.fullmatch(text):
        raise PlanError(f"{label} must be 1-64 simple ASCII letters, digits, '.', '_' or '-'")
    return text


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PlanError(f"{label} must be a non-empty string")
    return value.strip()


def _unique(values: Any, label: str) -> None:
    values = tuple(values)
    if len(values) != len(set(values)):
        raise PlanError(f"{label} ids must be unique")

