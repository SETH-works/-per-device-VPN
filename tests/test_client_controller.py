from pathlib import Path
import unittest

SCRIPT = Path(__file__).parents[1] / "client" / "walnuts-client.ps1"

class ClientControllerSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SCRIPT.read_text(encoding="utf-8")

    def test_lockdown_precedes_dns_and_exit_node_changes(self):
        guard = self.text.index("Add-LockdownRules $state\ntry {")
        dns = self.text.index("Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses")
        exit_select = self.text.index("--exit-node={0}")
        self.assertLess(guard, dns)
        self.assertLess(dns, exit_select)

    def test_arm_mode_never_selects_an_exit_node(self):
        arm = self.text.split("if ($Mode -eq 'Arm') {", 1)[1].split("  }", 1)[0]
        self.assertNotIn("--exit-node={0}", arm)
        self.assertIn("ARMED_BLOCKED", arm)

    def test_status_does_not_capture_or_write_a_new_baseline(self):
        status = self.text.split("if ($Mode -in @('Status','Verify')) {", 1)[1].split("$state=Save-Baseline", 1)[0]
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

    def test_vpn_dns_is_bound_to_detected_tailscale_interface(self):
        self.assertIn("TailscaleIfIndex=$adapter.ifIndex", self.text)
        self.assertIn("Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses", self.text)
        self.assertNotIn("InterfaceAlias $state.EthernetAlias -ServerAddresses", self.text)

    def test_direct_restores_both_ethernet_and_tailscale_dns(self):
        direct = self.text.split("function Switch-Direct", 1)[1].split("if ($PlanOnly) { Write-Warning", 1)[0]
        self.assertIn("InterfaceAlias $state.EthernetAlias -ResetServerAddresses", direct)
        self.assertIn("OriginalTailscaleDnsIPv4", direct)
        self.assertIn("InterfaceIndex $state.TailscaleIfIndex -ServerAddresses $originalTailscaleDns", direct)
        self.assertIn("InterfaceIndex $state.TailscaleIfIndex -ResetServerAddresses", direct)

    def test_effective_verifier_checks_disabled_and_conflicting_rules(self):
        assessment = self.text.split("function Test-RuleShape", 1)[1].split("function Set-ModeState", 1)[0]
        self.assertIn("$rule.Enabled -eq 'True'", assessment)
        self.assertIn("non_walnuts_ethernet_allow_rules", assessment)
        self.assertIn("tailscale_transport_program_mismatch", assessment)
        self.assertIn("dhcp_exception_scope_mismatch", assessment)

    def test_status_categories_are_observation_driven(self):
        for category in ("DIRECT", "ARMED_BLOCKED", "VPNBOOK_HEALTHY", "VPNBOOK_BLOCKED", "DEGRADED", "UNINITIALIZED"):
            self.assertIn("'" + category + "'", self.text)
        self.assertIn("$directOk", self.text)
        self.assertIn("$profileMismatch", self.text)

    def test_configuration_and_connectivity_verification_are_separate(self):
        self.assertIn("ValidateSet('Status','Verify'", self.text)
        self.assertIn("LiveConnectivityVerified", self.text)

if __name__ == "__main__":
    unittest.main()
