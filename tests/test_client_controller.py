"""Non-privileged behavioral tests; no packet-isolation claims."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "client" / "walnuts-client.ps1"
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")


@unittest.skipUnless(POWERSHELL, "PowerShell runtime unavailable")
class ClientControllerSafetyTests(unittest.TestCase):
    def test_status_reports_degraded_when_runtime_or_journal_is_unavailable(self):
        source = SCRIPT.read_text(encoding='utf-8').replace('#requires -RunAsAdministrator', '').replace('$PSScriptRoot', '$WalnutsTestRoot')
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests') as directory:
            for corrupt_journal in (False, True):
                with self.subTest(corrupt_journal=corrupt_journal):
                    if corrupt_journal:
                        journal = Path(directory) / 'Walnuts' / 'pc-stream-pilot.json'
                        journal.parent.mkdir()
                        journal.write_text('{broken', encoding='utf-8')
                    setup = "$WalnutsTestRoot='" + str(ROOT / 'client') + "'\n$env:COMPUTERNAME='STREAM'\n"
                    traps = '\n'.join('function ' + name + ' { throw "UNAVAILABLE" }' for name in (
                        'Get-NetAdapter', 'Get-CimInstance', 'Set-NetFirewallProfile', 'Set-DnsClientServerAddress', 'Remove-NetFirewallRule'))
                    command = setup + traps + '\n& {\n' + source + "\n} -Mode Status -ConfigPath '" + str(ROOT / 'client' / 'pilot-client.example.json') + "'"
                    run = subprocess.run([POWERSHELL, '-NoProfile', '-NonInteractive', '-EncodedCommand', base64.b64encode(command.encode('utf-16le')).decode('ascii')],
                        capture_output=True, text=True, env=dict(os.environ, ProgramData=directory), timeout=30)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertEqual(json.loads(run.stdout)['Status'], 'DEGRADED')
                    self.assertFalse(json.loads(run.stdout)['Protected'])

    def test_protection_gate_precedes_any_mutation_or_network_probe(self):
        # Remove only the elevation directive in memory to exercise the real
        # script without administrator privileges. Trap all effect commands.
        source = SCRIPT.read_text(encoding="utf-8").replace(
            "#requires -RunAsAdministrator", "").replace("$PSScriptRoot", "$WalnutsTestRoot")
        traps = "\n".join("function " + name + ' { throw "FORBIDDEN_EFFECT" }' for name in (
            "New-NetFirewallRule", "Set-NetFirewallProfile", "Set-DnsClientServerAddress",
            "Remove-NetFirewallRule", "Get-NetAdapter", "Get-CimInstance", "Invoke-RestMethod",
            "Resolve-DnsName", "Set-Content", "New-Item"))
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests') as directory:
            config = ROOT / "client" / "pilot-client.example.json"
            for mode in ("Arm", "VPNBOOK", "Verify"):
                for plan_only in (False, True):
                    with self.subTest(mode=mode, plan_only=plan_only):
                        setup = "$WalnutsTestRoot='" + str(ROOT / "client").replace("'", "''") + "'\n"
                        command = setup + traps + "\n& {\n" + source + "\n} -Mode " + mode + " -ConfigPath '" + str(config) + "'" + (" -PlanOnly" if plan_only else "")
                        encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
                        run = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                            capture_output=True, text=True, env=dict(os.environ, ProgramData=directory), timeout=30)
                        self.assertEqual(run.returncode, 2, run.stderr)
                        result = json.loads(run.stdout)
                        self.assertFalse(result["Protected"])
                        self.assertFalse(result["ChangesApplied"])
                        self.assertTrue(result["DeploymentBlocked"])
                        self.assertEqual(result["PlannedDns"]["IPv4"], ["1.1.1.1", "8.8.8.8"])
                        self.assertNotIn("FORBIDDEN_EFFECT", run.stderr)
                        self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
