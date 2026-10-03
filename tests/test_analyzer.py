"""Tests for the analyzer. Run with:  python3 -m unittest discover tests -v"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

import phish_analyzer as pa  # noqa: E402

SAMPLE = ROOT / "samples" / "invoice_overdue.eml"


class HelperTests(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(pa.defang("https://login-portal.example/x"), "hxxps://login-portal[.]example/x")

    def test_lookalike_detected(self):
        self.assertTrue(pa.looks_like("c0mpany-help.example", "company.example"))

    def test_real_domain_and_subdomain_not_flagged(self):
        self.assertFalse(pa.looks_like("company.example", "company.example"))
        self.assertFalse(pa.looks_like("mail.company.example", "company.example"))

    def test_unrelated_domain_not_flagged(self):
        self.assertFalse(pa.looks_like("university.example", "company.example"))


class SampleEmailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = pa.analyse(SAMPLE, "company.example")
        cls.ids = {f["id"] for f in cls.result["findings"]}

    def test_verdict_is_malicious(self):
        self.assertEqual(self.result["verdict"], "MALICIOUS")

    def test_authentication_results(self):
        self.assertEqual(self.result["authentication"], {"spf": "fail", "dkim": "none", "dmarc": "fail"})

    def test_origin_ip_is_first_hop(self):
        self.assertEqual(self.result["origin_ip"], "203.0.113.45")

    def test_key_findings_present(self):
        for expected in ("reply_to_mismatch", "lookalike_domain", "link_mismatch",
                         "risky_attachment", "double_extension", "urgency"):
            self.assertIn(expected, self.ids)

    def test_iocs_are_defanged(self):
        for url in self.result["iocs"]["urls"]:
            self.assertTrue(url.startswith("hxxp"))
        self.assertIn("login-portal[.]example", self.result["iocs"]["domains"])
        self.assertNotIn("company[.]example", self.result["iocs"]["domains"])


if __name__ == "__main__":
    unittest.main()
