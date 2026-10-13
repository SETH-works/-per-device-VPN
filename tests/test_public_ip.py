from datetime import datetime, timedelta, timezone
import unittest

from walnuts.health import EvidenceStatus, PublicIPResult


class PublicIPResultTests(unittest.TestCase):
    def test_global_ipv4_is_verified_only_while_fresh(self):
        now = datetime.now(timezone.utc)
        evidence = PublicIPResult.from_observation("1.1.1.1", now)
        self.assertEqual(evidence.status, EvidenceStatus.VERIFIED)
        self.assertTrue(evidence.verified(now=now))
        self.assertFalse(evidence.verified(now=now + timedelta(minutes=11)))

    def test_missing_private_and_invalid_addresses_do_not_verify(self):
        now = datetime.now(timezone.utc)
        self.assertEqual(PublicIPResult.from_observation(None, now).status,
                         EvidenceStatus.NOT_CHECKED)
        self.assertEqual(PublicIPResult.from_observation("192.168.1.41", now).status,
                         EvidenceStatus.FAILED)
        invalid = PublicIPResult.from_observation("not-an-ip", now)
        self.assertEqual(invalid.status, EvidenceStatus.FAILED)
        self.assertFalse(invalid.verified(now=now))


if __name__ == "__main__":
    unittest.main()
