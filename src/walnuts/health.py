"""Pure health-evidence checks; no network probes are performed here."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import ipaddress


class IPv6Evidence(StrEnum):
    TUNNELED = "TUNNELED"
    BLOCKED = "BLOCKED"
    NOT_CHECKED = "NOT_CHECKED"
    LEAKING = "LEAKING"


class CredentialState(StrEnum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class HealthEvidence:
    checked_at: datetime
    tunnel_up: bool
    public_ipv4: str | None
    dns_verified: bool
    ipv6: IPv6Evidence
    credential: CredentialState = CredentialState.UNKNOWN
    latency_ms: float | None = None
    packet_loss_percent: float | None = None

    def reasons_not_selectable(
        self,
        *,
        now: datetime | None = None,
        max_age: timedelta = timedelta(minutes=10),
        require_credential_confirmation: bool = True,
    ) -> tuple[str, ...]:
        """Return failed checks. Empty means evidence meets the selection bar.

        A handshake alone never proves internet egress. Evidence must show a
        valid observed public IPv4 address, intended DNS behavior, controlled
        IPv6, recent time, and non-expired credentials.
        """
        now = now or datetime.now(timezone.utc)
        reasons: list[str] = []
        checked = self.checked_at
        if checked.tzinfo is None:
            reasons.append("check_time_missing_timezone")
        else:
            age = now - checked.astimezone(timezone.utc)
            if age < timedelta(0):
                reasons.append("check_time_in_future")
            elif age > max_age:
                reasons.append("health_evidence_stale")
        if not self.tunnel_up:
            reasons.append("tunnel_down")
        if not _is_public_ipv4(self.public_ipv4):
            reasons.append("public_ipv4_not_verified")
        if not self.dns_verified:
            reasons.append("dns_not_verified")
        if self.ipv6 in (IPv6Evidence.NOT_CHECKED, IPv6Evidence.LEAKING):
            reasons.append("ipv6_not_protected")
        if self.credential is CredentialState.EXPIRED:
            reasons.append("credentials_expired")
        elif require_credential_confirmation and self.credential is CredentialState.UNKNOWN:
            reasons.append("credential_state_unknown")
        if self.latency_ms is not None and self.latency_ms < 0:
            reasons.append("latency_invalid")
        if self.packet_loss_percent is not None and not 0 <= self.packet_loss_percent <= 100:
            reasons.append("packet_loss_invalid")
        return tuple(reasons)

    def selectable(self, **kwargs: object) -> bool:
        return not self.reasons_not_selectable(**kwargs)


def _is_public_ipv4(value: str | None) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and address.is_global

