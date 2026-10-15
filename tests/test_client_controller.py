from pathlib import Path
import unittest

SCRIPT = Path(__file__).parents[1] / "client" / "walnuts-client.ps1"

class ClientControllerSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SCRIPT.read_text(encoding="utf-8")

    def test_lockdown_precedes_dns_and_exit_node_changes(self):
        guard = self.text.index("Add-LockdownRules $state\ntry {")
        dns = self.text.index("Set-DnsClientServerAddress -InterfaceAlias $state.EthernetAlias -ServerAddresses")
        exit_select = self.text.index("--exit-node={0}")
        self.assertLess(guard, dns)
        self.assertLess(dns, exit_select)

    def test_arm_mode_never_selects_an_exit_node(self):
        arm = self.text.split("if ($Mode -eq 'Arm') {", 1)[1].split("  }", 1)[0]
        self.assertNotIn("--exit-node={0}", arm)
        self.assertIn("ARMED_BLOCKED", arm)

    def test_status_does_not_capture_or_write_a_new_baseline(self):
        status = self.text.split("if ($Mode -eq 'Status') {", 1)[1].split("$state=Save-Baseline", 1)[0]
        self.assertIn("Show-Status", status)
        self.assertNotIn("Save-Baseline", status)
        self.assertNotIn("Set-", status)

    def test_vpnbook_error_does_not_call_direct_or_remove_firewall(self):
        catch = self.text.rsplit("} catch {", 1)[1].split("}\n", 1)[0]
        self.assertNotIn("Switch-Direct", catch)
        self.assertNotIn("Remove-NetFirewallRule", catch)
        self.assertIn("VPNBOOK_BLOCKED", catch)

    def test_kill_switch_blocks_outbound_and_ipv6(self):
        self.assertIn("-Enabled True -DefaultOutboundAction Block", self.text)
        self.assertIn("Block IPv6 egress", self.text)
        self.assertIn("-Protocol IPv6", self.text)

    def test_direct_requires_explicit_acknowledgement_and_restores_dhcp(self):
        self.assertIn("-ConfirmDirect", self.text)
        self.assertIn("-ResetServerAddresses", self.text)
        self.assertIn("EmergencyPhrase", self.text)

if __name__ == "__main__":
    unittest.main()
