"""Safe executable tests. Only self-test/invalid syntax; never opens BFE."""
import json
import subprocess
import unittest
from pathlib import Path

HELPER = Path(__file__).parents[1] / 'client/wfp/bin/Release/net11.0/Walnuts.Wfp.exe'


@unittest.skipUnless(HELPER.is_file(), 'Build the Windows x64 helper before executable validation')
class NativeHelperTests(unittest.TestCase):
    def test_offline_native_layout_and_property_tests(self):
        run = subprocess.run([str(HELPER), 'self-test'], capture_output=True, text=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        data = json.loads(run.stdout)
        self.assertFalse(data['NativeEngineOpened'])
        self.assertFalse(data['PacketTestsPerformed'])
        self.assertGreaterEqual(data['Passed'], 49)

    def test_mutations_require_explicit_lab_and_removal_confirmation(self):
        for args in (['arm'], ['remove'], ['arm', '--apply'], ['remove', '--disposable-vm', 'ec2173e9-996f-4341-8a96-4bb692848903']):
            with self.subTest(args=args):
                run = subprocess.run([str(HELPER), *args], capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
                self.assertFalse(json.loads(run.stdout)['Protected'])

    def test_invalid_guid_fails_before_configuration_or_engine_access(self):
        run = subprocess.run([str(HELPER), 'arm', '--disposable-vm', 'invalid'], capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 4, run.stdout + run.stderr)
        self.assertIn('deployment ID', json.loads(run.stdout)['Error'])


if __name__ == '__main__':
    unittest.main()
