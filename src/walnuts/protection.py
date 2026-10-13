"""Declarative DNS and IPv6 protection requirements for policy decisions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .health import IPv6Evidence
from .model import Policy


class DNSMode(StrEnum):
    UNSET = "UNSET"
    TUNNEL = "TUNNEL"
    PIHOLE = "PIHOLE"
    EXPLICIT_RESOLVER = "EXPLICIT_RESOLVER"


class IPv6Mode(StrEnum):
    UNSET = "UNSET"
    TUNNEL = "TUNNEL"
    BLOCK = "BLOCK"
    DIRECT = "DIRECT"


@dataclass(frozen=True, slots=True)
class ProtectionPolicy:
    dns: DNSMode = DNSMode.UNSET
    ipv6: IPv6Mode = IPv6Mode.UNSET

    def reasons_not_protected(
        self,
        policy: Policy,
        *,
        dns_verified: bool,
        observed_dns_mode: DNSMode | None,
        ipv6_evidence: IPv6Evidence,
    ) -> tuple[str, ...]:
        """Return unmet protections; VPN policies never silently allow bypass."""
        if policy in (Policy.DIRECT, Policy.DISABLED):
            return ()
        reasons: list[str] = []
        if self.dns is DNSMode.UNSET or not dns_verified:
            reasons.append("dns_protection_not_verified")
        if self.dns is not DNSMode.UNSET and observed_dns_mode is not None and observed_dns_mode is not self.dns:
            reasons.append("observed_dns_mode_mismatch")
        if self.ipv6 is IPv6Mode.UNSET:
            reasons.append("ipv6_policy_unset")
        elif self.ipv6 is IPv6Mode.DIRECT:
            reasons.append("ipv6_direct_bypass_for_vpn_policy")
        elif self.ipv6 is IPv6Mode.TUNNEL and ipv6_evidence is not IPv6Evidence.TUNNELED:
            reasons.append("ipv6_tunnel_not_verified")
        elif self.ipv6 is IPv6Mode.BLOCK and ipv6_evidence is not IPv6Evidence.BLOCKED:
            reasons.append("ipv6_block_not_verified")
        return tuple(reasons)
