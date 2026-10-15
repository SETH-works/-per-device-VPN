import json
import tempfile
import unittest
from pathlib import Path

from walnuts.pilot import PilotSpec
from walnuts.server_adapter import AdapterError, LinuxPilotAdapter
from walnuts.tailnet_policy import audit_exit_node_access, PILOT_TAG


def spec():
    return PilotSpec(client_name="PC-STREAM", client_tailscale_ipv4="100.70.142.17",
        client_tailscale_ipv6="fd7a:115c:a1e0::7f3b:8e11", dns_resolver_ipv4="1.1.1.1",
        direct_dns_resolver_ipv4="192.168.1.1", host_veth_ipv4="169.254.240.1/30",
        namespace_veth_ipv4="169.254.240.2/30", route_table=198, rule_priority=5000,
        firewall_backend="iptables-nft", tailscale_netfilter_mode="on")


class RecordingRunner:
    def __init__(self): self.calls=[]; self.host_table=None; self.rules4=[]; self.rules6=[]
    def __call__(self, argv, stdin=None):
        argv=tuple(argv); self.calls.append((argv,stdin))
        if argv[:4] == ("ip","link","show","dev") and argv[-1] == "tailscale0": return "tailscale0: <UP>"
        if argv[:2] == ("nft","list"):
            if self.host_table is None: raise AdapterError("table absent")
            return self.host_table
        if argv[:3] == ("ip","-4","rule") and argv[3:] == ("show",): return "\n".join(self.rules4)
        if argv[:3] == ("ip","-6","rule") and argv[3:] == ("show",): return "\n".join(self.rules6)
        if argv[:2] == ("nft","-f"):
            self.host_table=stdin or ""
        if argv[:4] == ("ip","-4","rule","add"): self.rules4.append("5001: from 100.70.142.17 iif tailscale0 unreachable")
        if argv[:4] == ("ip","-6","rule","add"): self.rules6.append("5000: from fd7a:115c:a1e0::7f3b:8e11 iif tailscale0 unreachable")
        return ""


class ServerAdapterTests(unittest.TestCase):
    def test_host_guard_is_client_scoped_and_has_no_shared_chain_mutation(self):
        adapter=LinuxPilotAdapter(spec(), runner=RecordingRunner(), is_root=True)
        nft=adapter._nft_host("abc")
        self.assertIn('ip saddr 100.70.142.17', nft)
        self.assertIn('ip6 saddr fd7a:115c:a1e0::7f3b:8e11', nft)
        self.assertIn('oifname != "wlnh0" counter drop', nft)
        self.assertNotIn('0x40000', nft)
        self.assertNotIn('flush ruleset', nft)

    def test_namespace_nat_is_scoped_to_pilot_veth_and_wireguard(self):
        adapter=LinuxPilotAdapter(spec(), runner=RecordingRunner(), is_root=True)
        nft=adapter._nft_namespace("abc")
        self.assertIn('iifname "wlnn0" ip saddr 169.254.240.1 oifname "wg-vpn" masquerade', nft)
        self.assertIn('iifname "wlnn0" counter drop', nft)

    def test_guard_journals_owned_objects_and_is_idempotent(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as d:
            runner=RecordingRunner(); adapter=LinuxPilotAdapter(spec(),state_path=Path(d)/"state.json",runner=runner,is_root=True)
            state=adapter.ensure_guard()
            self.assertEqual(state["phase"],"GUARDED")
            self.assertEqual(len(state["installed"]),3)
            mutations_before=sum(call[0][:2] == ("nft","-f") or call[0][:4] in (("ip","-4","rule","add"),("ip","-6","rule","add")) for call in runner.calls)
            adapter.ensure_guard()
            mutations_after=sum(call[0][:2] == ("nft","-f") or call[0][:4] in (("ip","-4","rule","add"),("ip","-6","rule","add")) for call in runner.calls)
            self.assertEqual(mutations_after,mutations_before)

    def test_guard_is_recreated_after_kernel_state_is_lost_on_reboot(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as d:
            runner=RecordingRunner(); adapter=LinuxPilotAdapter(spec(),state_path=Path(d)/"state.json",runner=runner,is_root=True)
            adapter.ensure_guard()
            runner.host_table=None; runner.rules4=[]; runner.rules6=[]
            adapter.ensure_guard()
            self.assertIsNotNone(runner.host_table)
            self.assertTrue(runner.rules4 and runner.rules6)
            state=json.loads((Path(d)/"state.json").read_text())
            self.assertEqual(state["phase"],"GUARDED")

    def test_status_rejects_stale_journal_when_live_guard_is_missing(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as d:
            runner=RecordingRunner(); adapter=LinuxPilotAdapter(spec(),state_path=Path(d)/"state.json",runner=runner,is_root=True)
            adapter.ensure_guard(); runner.host_table=None
            status=adapter.status()
            self.assertEqual(status["mode"],"DEGRADED")
            self.assertFalse(status["guarded"])

    def test_configured_values_replace_host_specific_constants(self):
        custom=PilotSpec(client_name="PC-STREAM", client_tailscale_ipv4="100.70.142.17",
            client_tailscale_ipv6="fd7a:115c:a1e0::7f3b:8e11", dns_resolver_ipv4="9.9.9.9",
            direct_dns_resolver_ipv4="192.168.1.1", host_veth_ipv4="169.254.240.1/30",
            namespace_veth_ipv4="169.254.240.2/30", route_table=198, rule_priority=4990,
            firewall_backend="iptables-nft", tailscale_netfilter_mode="on",
            expected_namespace_ipv4="10.0.0.9/32", expected_host_default="default via 10.0.0.1 dev eth0")
        adapter=LinuxPilotAdapter(custom, runner=RecordingRunner(), is_root=True)
        commands=adapter.commands()
        self.assertTrue(any("4990" in command for command in commands))
        self.assertTrue(any("4991" in command for command in commands))

    def test_failed_guard_command_records_partial_without_claiming_install(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as d:
            class Failing(RecordingRunner):
                def __call__(self, argv, stdin=None):
                    if tuple(argv)[:4] == ("ip","-4","rule","add"):
                        raise AdapterError("simulated failure")
                    return super().__call__(argv,stdin)
            runner=Failing(); adapter=LinuxPilotAdapter(spec(),state_path=Path(d)/"state.json",runner=runner,is_root=True)
            with self.assertRaises(AdapterError): adapter.ensure_guard()
            state=json.loads((Path(d)/"state.json").read_text())
            self.assertEqual(state["phase"],"BLOCKED_PARTIAL")
            self.assertEqual(state["installed"],["host_nft"])
            self.assertTrue(state["owned"])

    def test_teardown_requires_explicit_client_direct(self):
        adapter=LinuxPilotAdapter(spec(),runner=RecordingRunner(),is_root=True)
        with self.assertRaisesRegex(AdapterError,"switch PC-STREAM to DIRECT"):
            adapter.remove()

    def test_policy_audit_rejects_broader_existing_grants(self):
        policy={"tagOwners":{PILOT_TAG:["autogroup:admin"]},"grants":[
          {"src":[PILOT_TAG],"dst":["autogroup:internet"],"ip":["*"]},
          {"src":["*"],"dst":["autogroup:internet"],"ip":["*"]},
          {"src":["*"],"dst":["*"],"ip":["*"]}]}
        issues=audit_exit_node_access(policy,"100.70.142.17")
        self.assertTrue(any("nonpilot" in issue for issue in issues))

    def test_policy_audit_accepts_narrow_pilot_only_fragment(self):
        policy={"tagOwners":{PILOT_TAG:["autogroup:admin"]},"grants":[
          {"src":[PILOT_TAG],"dst":["autogroup:internet"],"ip":["*"]}]}
        self.assertEqual(audit_exit_node_access(policy,"100.70.142.17"),())

if __name__ == "__main__": unittest.main()
