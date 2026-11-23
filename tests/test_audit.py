import unittest
from datetime import datetime, timezone
from main import parse_document

class SecurityTxtTests(unittest.TestCase):
    def test_valid_minimum_document(self):
        report = parse_document(
            "Contact: mailto:security@example.org\nExpires: 2030-01-01T00:00:00Z\n",
            datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(report["errors"], 0)

    def test_missing_required_fields(self):
        report = parse_document("# comment\n")
        self.assertEqual(report["errors"], 2)

    def test_expired_timestamp_warns(self):
        report = parse_document(
            "Contact: https://example.org/security\nExpires: 2020-01-01T00:00:00Z\n",
            datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(report["warnings"], 1)

if __name__ == "__main__":
    unittest.main()
