from pathlib import Path
import shutil
import tempfile
import unittest

from verification import (
    EVIDENCE_ROOT,
    EXPECTED_RELEASE_ID,
    verify_c8a_bundle,
)


class C8AVerificationTests(unittest.TestCase):
    def test_frozen_bundle_passes(self) -> None:
        report = verify_c8a_bundle()

        self.assertTrue(
            report["accepted"],
            report["reasons"],
        )

    def test_release_identity_matches(self) -> None:
        report = verify_c8a_bundle()

        self.assertEqual(
            report["release_id"],
            EXPECTED_RELEASE_ID,
        )
        self.assertEqual(
            report["promotion_boundary"],
            "SHADOW_ONLY_NO_TRADE",
        )
        self.assertEqual(
            report["default_decision"],
            "NO_TRADE",
        )
        self.assertFalse(
            report["live_orders_allowed"]
        )

    def test_tampered_copy_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied_root = (
                Path(directory) / "evidence_root"
            )
            shutil.copytree(
                EVIDENCE_ROOT,
                copied_root,
            )

            attestation = (
                copied_root
                / "reports"
                / "track_b_candidate_evidence"
                / "FINAL_CANDIDATE_C8A"
                / (
                    "track_b_final_candidate_"
                    "attestation.json"
                )
            )

            text = attestation.read_text(
                encoding="utf-8"
            )
            attestation.write_text(
                text.replace(
                    '"live_orders_allowed": false',
                    '"live_orders_allowed": true',
                    1,
                ),
                encoding="utf-8",
            )

            report = verify_c8a_bundle(
                copied_root
            )

            self.assertFalse(report["accepted"])
            self.assertTrue(report["reasons"])


if __name__ == "__main__":
    unittest.main()
