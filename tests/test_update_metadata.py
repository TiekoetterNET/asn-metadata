import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from update_metadata import parse_whois_response  # noqa: E402


class ParseWhoisResponseTests(unittest.TestCase):
    def test_accepts_asnumber_range_containing_requested_asn(self) -> None:
        response = """
ASNumber: 701 - 705
ASName: UUNET

OrgName: Verizon Business
Country: US
"""

        self.assertEqual(
            parse_whois_response(703, response),
            {
                "as_name": "UUNET",
                "org_name": "Verizon Business",
                "country": "US",
                "country_name": "United States",
                "flag": "🇺🇸",
                "source": "whois",
            },
        )

    def test_rejects_asnumber_range_not_containing_requested_asn(self) -> None:
        response = """
ASNumber: 701 - 705
ASName: UUNET
"""

        with self.assertRaisesRegex(ValueError, "matching AS706 object"):
            parse_whois_response(706, response)

    def test_accepts_as_prefixed_range(self) -> None:
        response = """
aut-num: AS64496 - AS64511
as-name: DOCUMENTATION-RANGE
"""

        self.assertEqual(
            parse_whois_response(64500, response)["as_name"],
            "DOCUMENTATION-RANGE",
        )


if __name__ == "__main__":
    unittest.main()
