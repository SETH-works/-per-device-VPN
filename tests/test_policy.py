from datetime import datetime, timezone
import unittest

from walnuts.health import CredentialState, HealthEvidence, IPv6Evidence
from walnuts.model import Device, Exit, ExitProtocol, FailureAction, Policy
from walnuts.policy import DecisionKind, evaluate


NOW = datetime.now(timezone.utc)
GOOD = HealthEvidence(NOW, True, "1.1.1.1", True, IPv6Evidence.BLOCKED,
                      CredentialState.ACTIVE)
EXITS = {
    "DIRECT": Exit("DIRECT", "none", ExitProtocol.DIRECT),
    "US16": Exit("US16", "VPNBook", ExitProtocol.WIREGUARD, verified=True),
}


class PolicyTests(unittest.TestCase):
    def device(self, policy, **kwargs):
        return Device("pc-game", policy, identity_verified=True,
                      selector="reserved-ip:device-1", **kwargs)

    def test_direct_is_independent_of_vpn_health(self):
        decision = evaluate(self.device(Policy.DIRECT), EXITS, {})
        self.assertEqual(decision.kind, DecisionKind.DIRECT)

    def test_unverified_identity_never_resolves_to_route(self):
        device = Device("pc-game", Policy.DIRECT)
        self.assertEqual(evaluate(device, EXITS, {}).kind, DecisionKind.UNRESOLVED)

    def test_vpn_required_fails_closed_without_healthy_evidence(self):
        device = self.device(Policy.VPN_REQUIRED, exit_id="US16")
        result = evaluate(device, EXITS, {})
        self.assertEqual(result.kind, DecisionKind.BLOCK)

    def test_vpn_required_uses_verified_healthy_exit(self):
        device = self.device(Policy.VPN_REQUIRED, exit_id="US16")
        result = evaluate(device, EXITS, {"US16": GOOD})
        self.assertEqual(result.kind, DecisionKind.VPN)

    def test_selected_vpn_failure_action_is_explicit(self):
        device = self.device(Policy.SELECTED_VPN, exit_id="US16",
                             failure_action=FailureAction.DIRECT)
        result = evaluate(device, EXITS, {})
        self.assertEqual(result.kind, DecisionKind.DIRECT)
        self.assertEqual(result.reason, "selected_vpn_failed_open_by_policy")


if __name__ == "__main__":
    unittest.main()

