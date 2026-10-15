"""Offline, fail-closed planning for a single Tailscale-to-VPNBook pilot.

This module deliberately has no subprocess, socket, netlink, or file-writing
code. It validates operator-supplied observations and emits a dry-run plan;
it cannot configure a host or switch a client.
"""

from __future__ import annotations

from dataclasses import MISSING, dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
import tomllib
from typing import Iterable


@dataclass(frozen=True, slots=True)
class PilotSpec:
    client_name: str
    client_tailscale_ipv4: str
    client_tailscale_ipv6: str
    dns_resolver_ipv4: str
    direct_dns_resolver_ipv4: str
    host_veth_ipv4: str
    namespace_veth_ipv4: str
    route_table: int
    rule_priority: int
    firewall_backend: str
    tailscale_netfilter_mode: str
    namespace: str = "vpnbook"
    tunnel_interface: str = "wg-vpn"
    host_veth: str = "wlnh0"
    namespace_veth: str = "wlnn0"
    firewall_table: str = "walnuts_pilot"
    namespace_firewall_table: str = "walnuts_vpnbook_pilot"
    expected_vpn_ipv4: str = "147.135.15.16"
    expected_direct_ipv4: str = "198.29.53.14"
    expected_namespace_ipv4: str = "10.104.12.196/32"
    expected_host_default: str = "default via 192.168.1.1 dev eno1"


@dataclass(frozen=True, slots=True)
class PilotEvidence:
    """Live facts required before a generated plan may be called deployable."""

    client_identity_confirmed: bool = False
    only_client_granted_exit_node_access: bool = False
    forwarding_baseline_recorded: bool = False
    host_forwarding_values_known: bool = False
    namespace_default_via_tunnel_confirmed: bool = False
    namespace_kill_switch_confirmed: bool = False
    tailscale_source_pre_snat_confirmed: bool = False
    tailscale_snat_to_veth_confirmed: bool = False
    dns_resolver_reachable_only_via_tunnel: bool = False
    ipv6_drop_path_verified: bool = False
    firewall_backend_and_tailscale_mode_verified: bool = False
    nft_table_name_available: bool = False
    namespace_nft_table_name_available: bool = False
    route_table_available: bool = False
    rule_priority_available: bool = False
    veth_addresses_available: bool = False
    existing_forwarding_dependencies_reviewed: bool = False
    boot_guard_persistence_verified: bool = False
    ssh_and_protected_services_baselined: bool = False
    wg_handshake_recent: bool = False
    vpn_ipv4_verified: bool = False
    direct_ipv4_verified: bool = False


@dataclass(frozen=True, slots=True)
class PilotHealth:
    checked_at: datetime
    client_tailscale_ipv4: str
    client_tailscale_ipv6: str
    tunnel_up: bool
    tunnel_handshake_age_seconds: int | None
    observed_public_ipv4: str | None
    dns_query_succeeded: bool
    observed_dns_resolver_ipv4: str
    dns_egress_via_tunnel: bool
    ipv6_public_egress: str | None
    host_default_route_unchanged: bool
    protected_services_healthy: bool


@dataclass(frozen=True, slots=True)
class PilotPlan:
    ready: bool
    blockers: tuple[str, ...]
    configure_actions: tuple[str, ...]
    rollback_actions: tuple[str, ...]
    acceptance_checks: tuple[str, ...]


def load_pilot_plan(path: str | Path) -> PilotPlan:
    """Load a strict TOML dry-run specification; there is no apply operation."""
    with Path(path).open("rb") as stream:
        raw = tomllib.load(stream)
    if set(raw) != {"pilot", "evidence"}:
        raise ValueError("pilot plan must contain only [pilot] and [evidence]")
    pilot = raw["pilot"]
    evidence = raw["evidence"]
    if not isinstance(pilot, dict) or not isinstance(evidence, dict):
        raise ValueError("[pilot] and [evidence] must be tables")
    spec_fields = set(PilotSpec.__dataclass_fields__)
    evidence_fields = set(PilotEvidence.__dataclass_fields__)
    if set(pilot) - spec_fields:
        raise ValueError(f"unknown pilot fields: {', '.join(sorted(set(pilot) - spec_fields))}")
    if set(evidence) - evidence_fields:
        raise ValueError(f"unknown evidence fields: {', '.join(sorted(set(evidence) - evidence_fields))}")
    missing = {name for name, item in PilotSpec.__dataclass_fields__.items()
               if item.default is MISSING and item.default_factory is MISSING} - set(pilot)
    if missing:
        raise ValueError(f"missing pilot fields: {', '.join(sorted(missing))}")
    for field, value in pilot.items():
        if field in {"route_table", "rule_priority"}:
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"pilot.{field} must be an integer")
        elif not isinstance(value, str):
            raise ValueError(f"pilot.{field} must be a string")
    for field, value in evidence.items():
        if not isinstance(value, bool):
            raise ValueError(f"evidence.{field} must be a boolean")
    return build_pilot_plan(PilotSpec(**pilot), PilotEvidence(**evidence))


_REQUIRED_EVIDENCE = (
    ("client_identity_confirmed", "PC-STREAM Tailscale identity and stable IPv4/IPv6 source addresses are not verified"),
    ("only_client_granted_exit_node_access", "tailnet policy is not confirmed to grant exit-node use only to PC-STREAM"),
    ("forwarding_baseline_recorded", "current IPv4/IPv6 forwarding sysctls are not recorded"),
    ("host_forwarding_values_known", "existing forwarding values and their service dependencies are unknown"),
    ("namespace_default_via_tunnel_confirmed", "vpnbook default route through wg-vpn is unverified"),
    ("namespace_kill_switch_confirmed", "vpnbook kill-switch behavior is unverified"),
    ("tailscale_source_pre_snat_confirmed", "PC-STREAM source identity before host SNAT is unverified"),
    ("tailscale_snat_to_veth_confirmed", "Tailscale post-routing SNAT to the host veth and two-stage return NAT are unverified"),
    ("dns_resolver_reachable_only_via_tunnel", "approved DNS resolver and its tunnel-only path are unverified"),
    ("ipv6_drop_path_verified", "IPv6 fail-closed path for this client is unverified"),
    ("firewall_backend_and_tailscale_mode_verified", "firewall backend and Tailscale netfilter mode are unknown"),
    ("nft_table_name_available", "isolated firewall table name has not been checked for collision"),
    ("namespace_nft_table_name_available", "isolated namespace firewall table name has not been checked for collision"),
    ("route_table_available", "dedicated policy route table id has not been checked for collision"),
    ("rule_priority_available", "dedicated policy rule priority has not been checked for collision/order"),
    ("veth_addresses_available", "host-to-namespace veth addresses have not been checked for overlap"),
    ("existing_forwarding_dependencies_reviewed", "existing forwarded traffic dependencies have not been reviewed"),
    ("boot_guard_persistence_verified", "persistent boot-time fail-closed guards and ordering have not been verified"),
    ("ssh_and_protected_services_baselined", "SSH, Cloudflare, Pi-hole, Minecraft, Docker, and Tailscale baselines are incomplete"),
    ("wg_handshake_recent", "recent wg-vpn handshake has not been verified"),
    ("vpn_ipv4_verified", "VPNBook public IPv4 has not been verified from inside vpnbook"),
    ("direct_ipv4_verified", "normal direct public IPv4 baseline has not been verified"),
)


def build_pilot_plan(spec: PilotSpec, evidence: PilotEvidence) -> PilotPlan:
    """Return a dry-run checklist; never execute a generated action."""
    blockers = list(_validate_spec(spec))
    blockers.extend(message for key, message in _REQUIRED_EVIDENCE if not getattr(evidence, key))
    return PilotPlan(
        ready=not blockers,
        blockers=tuple(blockers),
        configure_actions=_configure_actions(spec) if not blockers else (),
        rollback_actions=_rollback_actions(spec) if not blockers else (),
        acceptance_checks=_acceptance_checks(spec) if not blockers else (),
    )


def check_pilot_health(
    health: PilotHealth,
    spec: PilotSpec,
    *,
    now: datetime | None = None,
    max_age: timedelta = timedelta(minutes=2),
    max_handshake_age: int = 180,
) -> tuple[str, ...]:
    """Validate post-switch observations. Any failed check means BLOCK."""
    now = now or datetime.now(timezone.utc)
    issues: list[str] = []
    if health.checked_at.tzinfo is None:
        issues.append("health_timestamp_missing_timezone")
    else:
        age = now - health.checked_at.astimezone(timezone.utc)
        if age < timedelta(0) or age > max_age:
            issues.append("health_evidence_stale")
    if health.client_tailscale_ipv4 != spec.client_tailscale_ipv4:
        issues.append("client_identity_mismatch")
    if health.client_tailscale_ipv6 != spec.client_tailscale_ipv6:
        issues.append("client_identity_mismatch")
    if not health.tunnel_up:
        issues.append("vpn_tunnel_down")
    if health.tunnel_handshake_age_seconds is None or not 0 <= health.tunnel_handshake_age_seconds <= max_handshake_age:
        issues.append("vpn_handshake_stale_or_unknown")
    if health.observed_public_ipv4 != spec.expected_vpn_ipv4:
        issues.append("vpn_public_ipv4_mismatch")
    if (not health.dns_query_succeeded
            or health.observed_dns_resolver_ipv4 != spec.dns_resolver_ipv4
            or not health.dns_egress_via_tunnel):
        issues.append("dns_failed_or_bypassed_tunnel")
    if health.ipv6_public_egress is not None:
        issues.append("ipv6_egress_not_blocked")
    if not health.host_default_route_unchanged:
        issues.append("host_default_route_changed")
    if not health.protected_services_healthy:
        issues.append("protected_service_health_failed")
    return tuple(issues)


def check_direct_health(
    health: PilotHealth,
    spec: PilotSpec,
    *,
    now: datetime | None = None,
    max_age: timedelta = timedelta(minutes=2),
) -> tuple[str, ...]:
    """Validate the intentional DIRECT mode independently of VPN health."""
    now = now or datetime.now(timezone.utc)
    issues: list[str] = []
    if health.checked_at.tzinfo is None:
        issues.append("health_timestamp_missing_timezone")
    else:
        age = now - health.checked_at.astimezone(timezone.utc)
        if age < timedelta(0) or age > max_age:
            issues.append("health_evidence_stale")
    if health.client_tailscale_ipv4 != spec.client_tailscale_ipv4:
        issues.append("client_identity_mismatch")
    if health.client_tailscale_ipv6 != spec.client_tailscale_ipv6:
        issues.append("client_identity_mismatch")
    if health.observed_public_ipv4 != spec.expected_direct_ipv4:
        issues.append("direct_public_ipv4_mismatch")
    if not health.dns_query_succeeded or health.observed_dns_resolver_ipv4 != spec.direct_dns_resolver_ipv4:
        issues.append("direct_dns_failed_or_resolver_mismatch")
    if health.dns_egress_via_tunnel:
        issues.append("direct_dns_unexpectedly_tunneled")
    if not health.host_default_route_unchanged:
        issues.append("host_default_route_changed")
    if not health.protected_services_healthy:
        issues.append("protected_service_health_failed")
    return tuple(issues)


def _validate_spec(spec: PilotSpec) -> Iterable[str]:
    if spec.client_name != "PC-STREAM":
        yield "pilot_is_limited_to_PC-STREAM"
    for label, value in (
        ("client Tailscale IPv4", spec.client_tailscale_ipv4),
        ("client Tailscale IPv6", spec.client_tailscale_ipv6),
        ("DNS resolver IPv4", spec.dns_resolver_ipv4),
        ("direct DNS resolver IPv4", spec.direct_dns_resolver_ipv4),
        ("expected VPN IPv4", spec.expected_vpn_ipv4),
        ("expected direct IPv4", spec.expected_direct_ipv4),
        ("expected namespace IPv4", spec.expected_namespace_ipv4.split("/", 1)[0]),
    ):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            yield f"{label} is missing or invalid"
    try:
        client = ipaddress.ip_address(spec.client_tailscale_ipv4)
        if client.version != 4 or not client in ipaddress.ip_network("100.64.0.0/10"):
            yield "client Tailscale address must be an IPv4 100.64.0.0/10 address"
    except ValueError:
        pass
    try:
        client6 = ipaddress.ip_address(spec.client_tailscale_ipv6)
        if client6.version != 6 or client6 not in ipaddress.ip_network("fd7a:115c:a1e0::/48"):
            yield "client Tailscale address must be an IPv6 address in the Tailscale ULA prefix"
    except ValueError:
        pass
    try:
        resolver = ipaddress.ip_address(spec.dns_resolver_ipv4)
        if resolver.version != 4 or not resolver.is_global:
            yield "DNS resolver must be an explicitly approved public IPv4 resolver"
    except ValueError:
        pass
    try:
        resolver = ipaddress.ip_address(spec.direct_dns_resolver_ipv4)
        if resolver.version != 4:
            yield "direct DNS resolver must be IPv4"
    except ValueError:
        pass
    for label, value in (("VPNBook", spec.expected_vpn_ipv4), ("direct", spec.expected_direct_ipv4)):
        try:
            address = ipaddress.ip_address(value)
            if address.version != 4 or not address.is_global:
                yield f"expected {label} egress must be a public IPv4 address"
        except ValueError:
            pass
    try:
        host = ipaddress.ip_interface(spec.host_veth_ipv4)
        peer = ipaddress.ip_interface(spec.namespace_veth_ipv4)
        if host.version != 4 or peer.version != 4 or host.network != peer.network or host.ip == peer.ip:
            yield "veth IPv4 addresses must be distinct addresses in one IPv4 subnet"
        elif host.network.prefixlen != 30 or host.ip not in host.network.hosts() or peer.ip not in peer.network.hosts():
            yield "veth addresses must be the two usable addresses of one dedicated /30 subnet"
    except ValueError:
        yield "veth IPv4 addresses must include valid prefix lengths"
    if spec.namespace != "vpnbook" or spec.tunnel_interface != "wg-vpn":
        yield "pilot namespace and tunnel must be vpnbook and wg-vpn"
    try:
        if ipaddress.ip_interface(spec.expected_namespace_ipv4).version != 4:
            yield "expected namespace tunnel address must be IPv4"
    except ValueError:
        yield "expected namespace tunnel address is invalid"
    if not spec.expected_host_default.startswith("default "):
        yield "expected host default route is invalid"
    if spec.firewall_backend != "iptables-nft":
        yield "this pilot requires the observed iptables-nft backend; do not install an independent nftables forwarding path"
    if spec.tailscale_netfilter_mode != "on":
        yield "this pilot requires verified Tailscale netfilter mode on"
    if not 1 <= spec.route_table <= 252:
        yield "route table id must be in 1..252 and reserved uniquely"
    if not 1 <= spec.rule_priority < 5209:
        yield "two consecutive rule priorities must precede Tailscale rules and be reserved uniquely"
    for label, value, maxlen in (
        ("host veth", spec.host_veth, 15),
        ("namespace veth", spec.namespace_veth, 15),
        ("firewall table", spec.firewall_table, 31),
        ("namespace firewall table", spec.namespace_firewall_table, 31),
    ):
        if not value or len(value) > maxlen or not value.replace("_", "").replace("-", "").isalnum():
            yield f"{label} name is invalid"


def _configure_actions(spec: PilotSpec) -> tuple[str, ...]:
    return (
        "Snapshot exact host sysctls, RPDB/routes, iptables-nft filter/NAT state, Tailscale status, and protected-service checks; arm timed rollback before changes.",
        "Install the persistent pilot-only unreachable/firewall guards and systemd boot ordering; verify from an isolated reboot rehearsal before advertising the exit node.",
        "Keep IPv6 forwarding disabled for this IPv4-only VPNBook pilot. Keep the currently enabled IPv4 forwarding value; do not change SethLinux's main/default route.",
        f"Create isolated veth pair {spec.host_veth}<->{spec.namespace_veth}; move only {spec.namespace_veth} into namespace {spec.namespace}; assign the reserved /30 addresses {spec.host_veth_ipv4} and {spec.namespace_veth_ipv4}.",
        f"In {spec.namespace}, retain the connected host-veth route and namespace default exclusively on {spec.tunnel_interface}; preserve Tailscale's host-side SNAT to {spec.host_veth_ipv4.split('/')[0]} and verify the two conntrack/NAT return stages.",
        f"Create dedicated route table {spec.route_table} defaulting to {spec.namespace_veth_ipv4.split('/')[0]} via {spec.host_veth}; add `ip rule` at priority {spec.rule_priority} matching iif tailscale0 + source {spec.client_tailscale_ipv4} to look up that table, then an unreachable fallback at {spec.rule_priority + 1}.",
        f"Add an IPv4 lookup at priority {spec.rule_priority}, its unreachable fallback at {spec.rule_priority + 1}, and a PC-STREAM IPv6 unreachable rule at {spec.rule_priority}; these precede Tailscale's 5210+ rules. In iptables-nft, create only the pilot-owned {spec.firewall_table} chain and one jump at the snapshot-verified point in FORWARD that preserves Tailscale classification/SNAT and precedes the drop path; allow this client's IPv4 flow only to {spec.host_veth}, drop its IPv6 and IPv4 fallback, and RETURN unrelated traffic so existing Docker/Tailscale rules still run.",
        f"Inside {spec.namespace}, add only pilot-owned filter/NAT chains and exact jumps after confirming the namespace ruleset: allow {spec.namespace_veth} to {spec.tunnel_interface}, allow established replies, masquerade only that IPv4 flow on {spec.tunnel_interface}, and drop any other pilot egress.",
        f"Set resolver {spec.dns_resolver_ipv4} for PC-STREAM's VPN mode and restore baseline resolver {spec.direct_dns_resolver_ipv4} for DIRECT mode; verify resolver and egress path in each mode. Do not reuse Pi-hole/upstream DNS until that path is proven safe.",
        "Only after firewall and rollback preflight: advertise SethLinux as an exit node, restrict tailnet exit-node permission to PC-STREAM, and have PC-STREAM explicitly select SethLinux with local-LAN access disabled.",
    )


def _rollback_actions(spec: PilotSpec) -> tuple[str, ...]:
    return (
        "On any failed health check, first set PC-STREAM exit node to None; do not alter SethLinux's main/default route.",
        "Withdraw only the exit-node advertisement created for this pilot; leave any pre-existing Tailscale state unchanged.",
        "Remove only the pilot's persistent guard configuration and systemd unit/drop-in after client opt-out and route cleanup; retain unrelated boot configuration.",
        f"Delete only the two policy rules at priorities {spec.rule_priority} and {spec.rule_priority + 1}, the PC-STREAM IPv6 unreachable rule, and the dedicated route table {spec.route_table} entries.",
        f"Remove only the exact pilot jump(s) and pilot-owned iptables-nft chains named {spec.firewall_table} and {spec.namespace_firewall_table}; preserve every other rule, chain, and table.",
        f"Delete host veth {spec.host_veth} (which removes its peer {spec.namespace_veth}) only after pilot route rules and advertisement are removed.",
        "Restore forwarding sysctl values from the captured snapshot only if this pilot changed them and no other approved forwarding dependency now requires them.",
        "Verify PC-STREAM DIRECT egress, original host default route, SSH/Tailscale reachability, Cloudflare, Pi-hole, Minecraft, Docker, and VPNBook baseline.",
    )


def _acceptance_checks(spec: PilotSpec) -> tuple[str, ...]:
    return (
        f"DIRECT: PC-STREAM selects no exit node and observes {spec.expected_direct_ipv4}; SethLinux retains its original default route.",
        f"VPNBOOK: PC-STREAM explicitly selects SethLinux and observes {spec.expected_vpn_ipv4}.",
        f"DNS: a unique test query resolves successfully and packet/evidence inspection confirms resolver {spec.dns_resolver_ipv4} was reached only over the VPNBook tunnel.",
        "IPv6: a public IPv6 probe from PC-STREAM fails closed; no direct public IPv6 egress is observed.",
        "Failure: with the tunnel unavailable in a controlled test window, PC-STREAM has no public IPv4/IPv6 egress; unrelated clients remain unaffected.",
        "Recovery: restore the tunnel, verify fresh health, then switch PC-STREAM between DIRECT and VPNBOOK again.",
        "Protected services: SSH/Tailscale, Cloudflare, Pi-hole, Minecraft, Docker, and the host default route match their captured baselines.",
    )
