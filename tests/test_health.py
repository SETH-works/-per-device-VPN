from datetime import datetime, timedelta, timezone
import unittest

from walnuts.health import CredentialState, HealthEvidence, IPv6Evidence


class HealthEvidenceTests(unittest.TestCase):
    def evidence(self, **changes):
        values = dict(
            checked_at=datetime.now(timezone.utc), tunnel_up=True,
            public_ipv4="1.1.1.1", dns_verified=True,
            ipv6=IPv6Evidence.TUNNELED, credential=CredentialState.ACTIVE,
            latency_ms=20, packet_loss_percent=0,
        )
        values.update(changes)
        return HealthEvidence(**values)

    def test_handshake_without_public_egress_is_not_selectable(self):
        result = self.evidence(public_ipv4=None)
        self.assertIn("public_ipv4_not_verified", result.reasons_not_selectable())

    def test_ipv6_not_checked_is_not_selectable(self):
        result = self.evidence(ipv6=IPv6Evidence.NOT_CHECKED)
        self.assertIn("ipv6_not_protected", result.reasons_not_selectable())

    def test_stale_evidence_is_not_selectable(self):
        old = datetime.now(timezone.utc) - timedelta(minutes=11)
        result = self.evidence(checked_at=old)
        self.assertIn("health_evidence_stale", result.reasons_not_selectable())

    def test_expired_credentials_are_not_selectable(self):
        result = self.evidence(credential=CredentialState.EXPIRED)
        self.assertIn("credentials_expired", result.reasons_not_selectable())

    def test_private_or_documentation_address_is_not_public_egress(self):
        result = self.evidence(public_ipv4="10.23.45.67")
        self.assertFalse(result.selectable())


if __name__ == "__main__":
    unittest.main()

