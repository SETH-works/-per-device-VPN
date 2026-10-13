"""Decision-only policy evaluation; it does not touch routes or firewalls."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .health import HealthEvidence
from .model import Device, Exit, FailureAction, Policy


class DecisionKind(StrEnum):
    DIRECT = "DIRECT"
    VPN = "VPN"
    BLOCK = "BLOCK"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True, slots=True)
class Decision:
    kind: DecisionKind
    exit_id: str | None
    reason: str


def evaluate(
    device: Device,
    exits: dict[str, Exit],
    health: dict[str, HealthEvidence],
) -> Decision:
    """Resolve intent using verified identity and current health evidence.

    The result is explanatory state only. No decision is applied to the host.
    """
    if not device.identity_verified or not device.selector:
        return Decision(DecisionKind.UNRESOLVED, None, "device_identity_unverified")
    if device.policy is Policy.DIRECT:
        return Decision(DecisionKind.DIRECT, "DIRECT", "direct_policy")
    if device.policy is Policy.DISABLED:
        return Decision(DecisionKind.BLOCK, None, "device_policy_disabled")
    if not device.exit_id or device.exit_id not in exits:
        return Decision(DecisionKind.UNRESOLVED, None, "vpn_exit_not_selected")

    exit = exits[device.exit_id]
    if exit.is_direct or not exit.verified:
        return Decision(DecisionKind.UNRESOLVED, exit.id, "vpn_exit_not_verified")
    evidence = health.get(exit.id)
    if evidence is not None and evidence.selectable():
        return Decision(DecisionKind.VPN, exit.id, "vpn_exit_healthy")

    if device.policy is Policy.VPN_REQUIRED:
        return Decision(DecisionKind.BLOCK, None, "vpn_required_exit_unhealthy")
    if device.policy is Policy.SELECTED_VPN:
        if device.failure_action is FailureAction.DIRECT:
            return Decision(DecisionKind.DIRECT, "DIRECT", "selected_vpn_failed_open_by_policy")
        if device.failure_action is FailureAction.BLOCK:
            return Decision(DecisionKind.BLOCK, None, "selected_vpn_failed_closed_by_policy")
        return Decision(DecisionKind.UNRESOLVED, None, "selected_vpn_failure_action_missing")
    return Decision(DecisionKind.UNRESOLVED, None, "unsupported_policy")

