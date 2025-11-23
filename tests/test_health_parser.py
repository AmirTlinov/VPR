import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from gui.vpr_studio.health_parser import parse_report, classify_suspicion


class HealthParserTest(unittest.TestCase):
    def test_parse_report_and_classify(self) -> None:
        payload = json.dumps(
            {
                "target": "alpha",
                "suspicion": 0.5,
                "generated_at": 123,
                "results": [
                    {
                        "transport": "doh",
                        "ok": True,
                        "latency_ms": 900,
                        "jitter_ms": 120,
                        "samples": 3,
                        "bytes_in": 1200,
                        "bytes_out": 600,
                        "detail": None,
                    }
                ],
            }
        )
        report = parse_report(payload)
        self.assertEqual(report.target, "alpha")
        self.assertEqual(report.severity, "WARN")
        self.assertEqual(len(report.transports), 1)
        self.assertTrue(report.transports[0].ok)

    def test_classify_thresholds(self) -> None:
        self.assertEqual(classify_suspicion(0.2), "OK")
        self.assertEqual(classify_suspicion(0.5), "WARN")
        self.assertEqual(classify_suspicion(0.9), "CRITICAL")


class HealthHistoryCliTest(unittest.TestCase):
    def test_cli_json_output(self) -> None:
        payload = {
            "target": "beta",
            "suspicion": 0.3,
            "generated_at": 456,
            "results": [],
        }
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            tmp.write(json.dumps(payload) + "\n")
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/health-history.py",
                    "--path",
                    str(tmp_path),
                    "--tail",
                    "1",
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
        finally:
            tmp_path.unlink(missing_ok=True)
        parsed = json.loads(result.stdout)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["target"], "beta")


if __name__ == "__main__":
    unittest.main()
