import unittest

from walnuts.plan import PlanError, parse_plan


BASE = {
    "schema_version": 1,
    "exits": [
        {"id": "DIRECT", "provider": "none", "protocol": "DIRECT"},
        {"id": "US16", "provider": "VPNBook", "protocol": "WIREGUARD", "verified": False},
    ],
    "devices": [],
}


class PlanTests(unittest.TestCase):
    def test_example_shape_is_accepted(self):
        plan = parse_plan(BASE)
        self.assertEqual(len(plan.exits), 2)
        self.assertEqual(plan.devices, ())

    def test_unknown_fields_are_rejected(self):
        raw = dict(BASE)
        raw["private_key"] = "must-not-be-accepted"
        with self.assertRaisesRegex(PlanError, "unknown fields"):
            parse_plan(raw)

    def test_vpn_required_cannot_fail_open(self):
        raw = dict(BASE)
        raw["devices"] = [{
            "id": "pc-game", "policy": "VPN_REQUIRED", "exit_id": "US16",
            "failure_action": "DIRECT",
        }]
        with self.assertRaisesRegex(PlanError, "always fails closed"):
            parse_plan(raw)

    def test_selected_vpn_requires_explicit_failure_action(self):
        raw = dict(BASE)
        raw["devices"] = [{"id": "pc-game", "policy": "SELECTED_VPN", "exit_id": "US16"}]
        with self.assertRaisesRegex(PlanError, "requires an explicit failure_action"):
            parse_plan(raw)

    def test_selector_requires_verified_identity(self):
        raw = dict(BASE)
        raw["devices"] = [{"id": "pc-game", "policy": "DIRECT", "selector": "mac:unknown"}]
        with self.assertRaisesRegex(PlanError, "before identity verification"):
            parse_plan(raw)


if __name__ == "__main__":
    unittest.main()

