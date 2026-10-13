from datetime import datetime, timedelta, timezone
import unittest

from walnuts.exits import EndpointState, ExitObservation, SelectionState, select_exit
from walnuts.model import Exit, ExitProtocol


class ExitSelectionTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.direct = Exit("DIRECT", "none", ExitProtocol.DIRECT)
        self.us16 = Exit("US16", "VPNBook", ExitProtocol.WIREGUARD, verified=True)
        self.us178 = Exit("US178", "VPNBook", ExitProtocol.WIREGUARD, verified=False)

    def test_direct_selection_does_not_depend_on_vpn_observation(self):
        result = select_exit([self.direct, self.us16], "DIRECT", {}, now=self.now)
        self.assertEqual((result.state, result.exit_id), (SelectionState.SELECTED, "DIRECT"))

    def test_unknown_exit_is_unresolved(self):
        result = select_exit([self.direct, self.us16], "MISSING", {}, now=self.now)
        self.assertEqual(result.reason, "exit_not_configured")

    def test_unverified_candidate_cannot_be_selected(self):
        result = select_exit([self.direct, self.us178], "US178", {}, now=self.now)
        self.assertEqual(result.reason, "exit_unverified")

    def test_available_verified_exit_can_be_manually_selected(self):
        observation = ExitObservation("US16", EndpointState.AVAILABLE, self.now)
        result = select_exit([self.us16], "US16", {"US16": observation}, now=self.now)
        self.assertEqual((result.state, result.reason), (SelectionState.SELECTED, "exit_available"))

    def test_unavailable_and_stale_exits_are_not_selectable(self):
        unavailable = ExitObservation("US16", EndpointState.UNAVAILABLE, self.now)
        stale = ExitObservation("US16", EndpointState.AVAILABLE, self.now - timedelta(minutes=11))
        self.assertEqual(select_exit([self.us16], "US16", {"US16": unavailable}, now=self.now).reason,
                         "exit_unavailable")
        self.assertEqual(select_exit([self.us16], "US16", {"US16": stale}, now=self.now).reason,
                         "exit_status_stale")

    def test_invalid_observation_state_is_not_treated_as_available(self):
        invalid = ExitObservation("US16", "AVAILABLE", self.now)
        result = select_exit([self.us16], "US16", {"US16": invalid}, now=self.now)
        self.assertEqual(result.reason, "endpoint_state_invalid")

    def test_observation_must_match_selected_exit(self):
        mismatched = ExitObservation("US178", EndpointState.AVAILABLE, self.now)
        result = select_exit([self.us16], "US16", {"US16": mismatched}, now=self.now)
        self.assertEqual(result.reason, "exit_status_identity_mismatch")


if __name__ == "__main__":
    unittest.main()
