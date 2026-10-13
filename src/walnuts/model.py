"""Provider-neutral configuration types with conservative defaults."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Policy(StrEnum):
    DIRECT = "DIRECT"
    SELECTED_VPN = "SELECTED_VPN"
    VPN_REQUIRED = "VPN_REQUIRED"
    DISABLED = "DISABLED"


class FailureAction(StrEnum):
    BLOCK = "BLOCK"
    DIRECT = "DIRECT"


class ExitProtocol(StrEnum):
    DIRECT = "DIRECT"
    WIREGUARD = "WIREGUARD"
    OPENVPN = "OPENVPN"


@dataclass(frozen=True, slots=True)
class Exit:
    id: str
    provider: str
    protocol: ExitProtocol
    verified: bool = False
    credential_ref: str | None = None

    @property
    def is_direct(self) -> bool:
        return self.protocol is ExitProtocol.DIRECT


@dataclass(frozen=True, slots=True)
class Device:
    id: str
    policy: Policy
    exit_id: str | None = None
    failure_action: FailureAction | None = None
    identity_verified: bool = False
    selector: str | None = None


@dataclass(frozen=True, slots=True)
class Plan:
    schema_version: int
    exits: tuple[Exit, ...]
    devices: tuple[Device, ...]

