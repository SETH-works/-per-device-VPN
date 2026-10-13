"""Explicit VPN-exit inventory and manual selection decisions.

This module only evaluates recorded evidence. It never probes or configures a
VPN endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Iterable

from .model import Exit


class EndpointState(StrEnum):
    UNVERIFIED = "UNVERIFIED"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class SelectionState(StrEnum):
    SELECTED = "SELECTED"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True, slots=True)
class ExitObservation:
    """A non-secret, timestamped observation about one configured exit."""

    exit_id: str
    state: EndpointState
    checked_at: datetime
    reason: str = ""

    def fresh(self, *, now: datetime | None = None,
              max_age: timedelta = timedelta(minutes=10)) -> bool:
        now = now or datetime.now(timezone.utc)
        if self.checked_at.tzinfo is None:
            return False
        age = now - self.checked_at.astimezone(timezone.utc)
        return timedelta(0) <= age <= max_age


@dataclass(frozen=True, slots=True)
class ExitSelection:
    state: SelectionState
    exit_id: str | None
    reason: str


def select_exit(
    exits: Iterable[Exit],
    exit_id: str,
    observations: dict[str, ExitObservation],
    *,
    now: datetime | None = None,
    max_age: timedelta = timedelta(minutes=10),
) -> ExitSelection:
    """Resolve an explicit selection; DIRECT remains independent of VPN health."""
    by_id = {item.id: item for item in exits}
    selected = by_id.get(exit_id)
    if selected is None:
        return ExitSelection(SelectionState.UNRESOLVED, None, "exit_not_configured")
    if selected.is_direct:
        return ExitSelection(SelectionState.SELECTED, selected.id, "direct_route_selected")
    if not selected.verified:
        return ExitSelection(SelectionState.UNRESOLVED, selected.id, "exit_unverified")
    observation = observations.get(selected.id)
    if observation is None:
        return ExitSelection(SelectionState.UNRESOLVED, selected.id, "exit_status_not_checked")
    if observation.exit_id != selected.id:
        return ExitSelection(SelectionState.UNRESOLVED, selected.id, "exit_status_identity_mismatch")
    if not observation.fresh(now=now, max_age=max_age):
        return ExitSelection(SelectionState.UNRESOLVED, selected.id, "exit_status_stale")
    if observation.state is EndpointState.UNAVAILABLE:
        return ExitSelection(SelectionState.UNRESOLVED, selected.id, "exit_unavailable")
    if observation.state is EndpointState.UNVERIFIED:
        return ExitSelection(SelectionState.UNRESOLVED, selected.id, "endpoint_unverified")
    if observation.state is not EndpointState.AVAILABLE:
        return ExitSelection(SelectionState.UNRESOLVED, selected.id, "endpoint_state_invalid")
    return ExitSelection(SelectionState.SELECTED, selected.id, "exit_available")
