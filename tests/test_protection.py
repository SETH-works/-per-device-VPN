import unittest

from walnuts.health import IPv6Evidence
from walnuts.model import Policy
from walnuts.protection import DNSMode, IPv6Mode, ProtectionPolicy


class ProtectionPolicyTests(unittest.TestCase):
    def test_vpn_policy_requires_verified_matching_dns_and_ipv6_protection(self):
        policy = ProtectionPolicy(DNSMode.PIHOLE, IPv6Mode.BLOCK)
        reasons = policy.reasons_not_protected(
            Policy.VPN_REQUIRED, dns_verified=True, observed_dns_mode=DNSMode.PIHOLE,
            ipv6_evidence=IPv6Evidence.BLOCKED,
        )
        self.assertEqual(reasons, ())

    def test_unset_or_mismatched_dns_and_ipv6_are_rejected(self):
        policy = ProtectionPolicy(DNSMode.TUNNEL, IPv6Mode.TUNNEL)
        reasons = policy.reasons_not_protected(
            Policy.VPN_REQUIRED, dns_verified=False, observed_dns_mode=DNSMode.PIHOLE,
            ipv6_evidence=IPv6Evidence.BLOCKED,
        )
        self.assertIn("dns_protection_not_verified", reasons)
        self.assertIn("observed_dns_mode_mismatch", reasons)
        self.assertIn("ipv6_tunnel_not_verified", reasons)

    def test_direct_policy_keeps_direct_dns_and_ipv6_exception(self):
        policy = ProtectionPolicy()
        self.assertEqual(policy.reasons_not_protected(
            Policy.DIRECT, dns_verified=False, observed_dns_mode=None,
            ipv6_evidence=IPv6Evidence.NOT_CHECKED,
        ), ())


if __name__ == "__main__":
    unittest.main()
