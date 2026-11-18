
import unittest
from unittest.mock import patch

from web_comparison import compare_web_assessments


class TestWebsiteComparison(unittest.TestCase):

    @patch("web_comparison.get_assessment")
    def test_changed_security_header(self, mock_get):
        old = {
            "id": 100,
            "timestamp": "2026-11-17T10:00:00+00:00",
            "target_url": "http://127.0.0.1:3000/",
            "http_evidence": {
                "assessment_type": "web",
                "url": "http://127.0.0.1:3000/",
                "status_code": 200,
            },
            "all_findings": [
                {
                    "name": "Content Security Policy (CSP)",
                    "status": "Needs Verification",
                    "severity": "Informational",
                    "evidence": "content-security-policy header not present in response",
                }
            ],
        }

        new = {
            "id": 101,
            "timestamp": "2026-11-18T10:00:00+00:00",
            "target_url": "http://127.0.0.1:3000/",
            "http_evidence": {
                "assessment_type": "web",
                "url": "http://127.0.0.1:3000/",
                "status_code": 200,
            },
            "all_findings": [
                {
                    "name": "Content Security Policy (CSP)",
                    "status": "Observed",
                    "severity": "Informational",
                    "evidence": "content-security-policy: default-src 'self'",
                }
            ],
        }

        mock_get.side_effect = lambda assessment_id: {
            100: old,
            101: new,
        }.get(assessment_id)

        result = compare_web_assessments(100, 101)

        self.assertEqual(len(result["changed_findings"]), 1)
        self.assertEqual(len(result["added_findings"]), 0)
        self.assertEqual(len(result["removed_findings"]), 0)

        changed = result["changed_findings"][0]

        self.assertEqual(
            changed["name"],
            "Content Security Policy (CSP)",
        )
        self.assertEqual(
            changed["previous_status"],
            "Needs Verification",
        )
        self.assertEqual(
            changed["current_status"],
            "Observed",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
