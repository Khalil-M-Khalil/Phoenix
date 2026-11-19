import os
import sys
import unittest

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from threat_engine import (
    URLThreatEngine,
    TelecomThreatEngine,
    ForensicMediaEngine,
    ForensicDossierBuilder
)


class TestPhoenixThreatEngine(unittest.TestCase):

    def setUp(self):
        self.url_engine = URLThreatEngine(timeout=5)

    def test_telecom_voip_detection(self):
        # Test known VoIP carrier
        res_voip = TelecomThreatEngine.assess_number("Twilio Inc.", "VOIP", "1")
        self.assertTrue(res_voip["is_virtual_voip"])
        self.assertIn("CRITICAL", res_voip["anonymity_tier"])
        self.assertGreaterEqual(res_voip["risk_score"], 40)

        # Test physical carrier
        res_phys = TelecomThreatEngine.assess_number("Syrian Telecommunications MTN", "MOBILE", "963")
        self.assertFalse(res_phys["is_virtual_voip"])
        self.assertIn("STANDARD", res_phys["anonymity_tier"])

    def test_dossier_generation(self):
        evidence = [
            {
                "title": "Phishing Link Investigation",
                "target": "https://verify-account-security-meta.xyz",
                "risk_level": "CRITICAL",
                "threat_score": 92,
                "summary": "Spoofed Instagram favicon + Domain age 2 days",
                "indicators": ["Favicon hash match", "Domain age < 14 days"]
            }
        ]
        report = ForensicDossierBuilder.build_markdown_report("Case Meta Harassment", evidence)
        self.assertIn("PHOENIX FORENSIC INCIDENT DOSSIER", report)
        self.assertIn("CRITICAL", report)
        self.assertIn("verify-account-security-meta.xyz", report)

    def test_rdap_telemetry(self):
        telemetry = self.url_engine._fetch_rdap("google.com")
        self.assertIsNotNone(telemetry.registered_date)
        self.assertFalse(telemetry.is_recently_registered)
        self.assertGreater(telemetry.age_days, 365)


if __name__ == "__main__":
    unittest.main()
