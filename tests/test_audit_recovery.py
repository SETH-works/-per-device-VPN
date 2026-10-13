from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from walnuts.audit import AuditRecord, JsonlAuditLog
from walnuts.policy import Decision, DecisionKind
from walnuts.recovery import RecoveryState, assess_recovery


class AuditTests(unittest.TestCase):
    def test_jsonl_log_appends_narrow_non_secret_records(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd() / "local") as directory:
            path = Path(directory) / "walnuts" / "audit.jsonl"
            log = JsonlAuditLog(path)
            log.append(AuditRecord(datetime.now(timezone.utc), "policy_decision", "pc_game",
                                   "BLOCK", "vpn_exit_unhealthy"))
            row = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(row["subject_id"], "pc_game")
            self.assertNotIn("credential", row)
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 1)

    def test_rejects_unsafe_arbitrary_values(self):
        record = AuditRecord(datetime.now(timezone.utc), "decision", "pc_game",
                             "BLOCK", "private key material")
        with self.assertRaises(ValueError):
            record.to_json()


class RecoveryTests(unittest.TestCase):
    def test_vpn_required_block_is_explicitly_blocked(self):
        result = assess_recovery(Decision(DecisionKind.BLOCK, None, "vpn_required_exit_unhealthy"))
        self.assertEqual(result.state, RecoveryState.BLOCKED)
        self.assertFalse(result.rollback_required)

    def test_inconsistent_state_requires_review_and_rollback(self):
        result = assess_recovery(Decision(DecisionKind.VPN, "US16", "vpn_exit_healthy"),
                                 state_consistent=False)
        self.assertEqual(result.state, RecoveryState.REVIEW_REQUIRED)
        self.assertTrue(result.rollback_required)


if __name__ == "__main__":
    unittest.main()
