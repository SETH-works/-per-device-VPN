"""Recovery status modeling; this module does not execute rollback actions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .policy import Decision, DecisionKind


class RecoveryState(StrEnum):
    READY = "READY"
    DIRECT_EXCEPTION = "DIRECT_EXCEPTION"
    DEGRADED = "DEGRADED"
    BLOCKED = "BLOCKED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


@dataclass(frozen=True, slots=True)
class RecoveryAssessment:
    state: RecoveryState
    reason: str
    rollback_required: bool = False


def assess_recovery(decision: Decision, *, state_consistent: bool = True) -> RecoveryAssessment:
    """Describe recovery posture from a decision and an observed state flag."""
    if not state_consistent:
        return RecoveryAssessment(RecoveryState.REVIEW_REQUIRED,
                                  "observed_state_differs_from_policy", True)
    if decision.kind is DecisionKind.VPN:
        return RecoveryAssessment(RecoveryState.READY, "vpn_policy_and_evidence_ready")
    if decision.kind is DecisionKind.DIRECT:
        if decision.reason == "selected_vpn_failed_open_by_policy":
            return RecoveryAssessment(RecoveryState.DIRECT_EXCEPTION,
                                      "explicit_selected_vpn_fallback")
        return RecoveryAssessment(RecoveryState.READY, "direct_policy_ready")
    if decision.kind is DecisionKind.BLOCK:
        return RecoveryAssessment(RecoveryState.BLOCKED, decision.reason)
    return RecoveryAssessment(RecoveryState.DEGRADED, decision.reason)
