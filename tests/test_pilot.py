from dataclasses import replace
from datetime import datetime, timedelta, timezone
import tempfile
from pathlib import Path
import unittest

from walnuts.pilot import (
    PilotEvidence,
    PilotHealth,
    PilotSpec,
    build_pilot_plan,
    check_direct_health,
    check_pilot_health,
    load_pilot_plan,
)


def ready_spec() -> PilotSpec:
    return PilotSpec(
        client_name="PC-STREAM",
        client_tailscale_ipv4="100.112.153.82",
        client_tailscale_ipv6="fd7a:115c:a1e0::82",
        dns_resolver_ipv4="1.1.1.1",
        direct_dns_resolver_ipv4="192.168.1.41",
        host_veth_ipv4="169.254.254.1/30",
        namespace_veth_ipv4="169.254.254.2/30",
        route_table=198,
        rule_priority=5000,
        firewall_backend="iptables-nft",
        tailscale_netfilter_mode="on",
    )


class PilotPlanTests(unittest.TestCase):
    def test_unknown_live_evidence_blocks_and_emits_no_actions(self):
        plan = build_pilot_plan(ready_spec(), PilotEvidence())
        self.assertFalse(plan.ready)
        self.assertTrue(plan.blockers)
        self.assertEqual(plan.configure_actions, ())
        self.assertEqual(plan.rollback_actions, ())

    def test_complete_evidence_creates_scoped_review_plan_only(self):
        spec = ready_spec()
        evidence = PilotEvidence(**{field: True for field in PilotEvidence.__dataclass_fields__})
        plan = build_pilot_plan(spec, evidence)
        self.assertTrue(plan.ready)
        self.assertFalse(plan.blockers)
        self.assertTrue(any("tailscale0" in action and spec.client_tailscale_ipv4 in action
                            for action in plan.configure_actions))
        self.assertTrue(any(spec.firewall_table in action for action in plan.rollback_actions))
        self.assertIn("IPv6: a public IPv6 probe from PC-STREAM fails closed; no direct public IPv6 egress is observed.",
                      plan.acceptance_checks)

    def test_refuses_other_devices_and_rule_priority_collision(self):
        spec = ready_spec()
        evidence = PilotEvidence(**{field: True for field in PilotEvidence.__dataclass_fields__})
        wrong_device = build_pilot_plan(replace(spec, client_name="OTHER-PC"), evidence)
        collision = build_pilot_plan(replace(spec, rule_priority=5209), evidence)
        self.assertIn("pilot_is_limited_to_PC-STREAM", wrong_device.blockers)
        self.assertTrue(any("precede Tailscale" in item for item in collision.blockers))

    def test_invalid_veth_subnet_is_blocked(self):
        spec = ready_spec()
        bad = replace(spec, host_veth_ipv4="192.168.1.10/24", namespace_veth_ipv4="192.168.1.11/24")
        evidence = PilotEvidence(**{field: True for field in PilotEvidence.__dataclass_fields__})
        plan = build_pilot_plan(bad, evidence)
        self.assertTrue(any("dedicated /30" in item for item in plan.blockers))

    def test_health_blocks_tunnel_or_dns_failure_and_ipv6_leak(self):
        spec = ready_spec()
        now = datetime.now(timezone.utc)
        health = PilotHealth(
            checked_at=now,
            client_tailscale_ipv4=spec.client_tailscale_ipv4,
            client_tailscale_ipv6=spec.client_tailscale_ipv6,
            tunnel_up=False,
            tunnel_handshake_age_seconds=None,
            observed_public_ipv4="198.29.53.14",
            dns_query_succeeded=False,
            observed_dns_resolver_ipv4="1.1.1.1",
            dns_egress_via_tunnel=False,
            ipv6_public_egress="2001:db8::1",
            host_default_route_unchanged=True,
            protected_services_healthy=True,
        )
        issues = check_pilot_health(health, spec, now=now)
        self.assertIn("vpn_tunnel_down", issues)
        self.assertIn("vpn_public_ipv4_mismatch", issues)
        self.assertIn("dns_failed_or_bypassed_tunnel", issues)
        self.assertIn("ipv6_egress_not_blocked", issues)

    def test_stale_health_blocks_and_direct_mode_is_separate(self):
        spec = ready_spec()
        now = datetime.now(timezone.utc)
        health = PilotHealth(
            checked_at=now - timedelta(minutes=5),
            client_tailscale_ipv4=spec.client_tailscale_ipv4,
            client_tailscale_ipv6=spec.client_tailscale_ipv6,
            tunnel_up=False,
            tunnel_handshake_age_seconds=None,
            observed_public_ipv4=spec.expected_direct_ipv4,
            dns_query_succeeded=True,
            observed_dns_resolver_ipv4="192.168.1.41",
            dns_egress_via_tunnel=False,
            ipv6_public_egress=None,
            host_default_route_unchanged=True,
            protected_services_healthy=True,
        )
        self.assertIn("health_evidence_stale", check_pilot_health(health, spec, now=now))
        self.assertIn("health_evidence_stale", check_direct_health(health, spec, now=now))
        fresh_direct = replace(health, checked_at=now)
        self.assertEqual(check_direct_health(fresh_direct, spec, now=now), ())

    def test_example_template_is_blocked_and_loader_rejects_unknown_fields(self):
        template = Path(__file__).parents[1] / "config" / "pilot.example.toml"
        plan = load_pilot_plan(template)
        self.assertFalse(plan.ready)
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            bad_file = Path(directory) / "bad.toml"
            bad_file.write_text("[pilot]\nunknown = true\n[evidence]\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown pilot fields"):
                load_pilot_plan(bad_file)
            missing_file = Path(directory) / "missing.toml"
            missing_file.write_text("[pilot]\nclient_name='PC-STREAM'\n[evidence]\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing pilot fields"):
                load_pilot_plan(missing_file)


if __name__ == "__main__":
    unittest.main()
