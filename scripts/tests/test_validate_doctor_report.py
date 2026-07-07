#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


VALIDATOR = Path(__file__).resolve().parents[1] / "validate-doctor-report.py"


def valid_report(expected=2, actual=2):
    return {
        "status": "ok",
        "exit_code": 0,
        "schema_version_expected": expected,
        "schema_version_actual": actual,
        "checks": [],
    }


class ValidateDoctorReportTests(unittest.TestCase):
    def run_validator(self, report):
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", suffix=".json", delete=False
        ) as handle:
            json.dump(report, handle)
            path = Path(handle.name)
        self.addCleanup(path.unlink, missing_ok=True)
        return subprocess.run(
            [sys.executable, str(VALIDATOR), str(path)],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_accepts_matching_current_schema_version(self):
        result = self.run_validator(valid_report(expected=2, actual=2))

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_rejects_schema_version_mismatch(self):
        result = self.run_validator(valid_report(expected=2, actual=1))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("schema_version", result.stderr)


if __name__ == "__main__":
    unittest.main()
