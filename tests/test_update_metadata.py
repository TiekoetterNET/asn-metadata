import contextlib
import subprocess
import sys
import unittest
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from update_metadata import (  # noqa: E402
    WhoisClient,
    parse_whois_response,
    update_metadata,
)

ARIN_OBJECT = """
ASNumber:       199177
ASName:         AS199177

OrgName:        Ssmidge Technologies
Country:        CA
"""

UNMANAGED_BLOCK = """
as-block:       AS199177 - AS199177
descr:          ASN block not managed by the RIPE NCC
source:         RIPE
"""


@contextlib.contextmanager
def fake_whois(
    responses: dict[str | None, tuple[str, int]],
) -> Iterator[list[str | None]]:
    """Replace the WHOIS client with canned ``(output, exit status)`` answers.

    Answers are keyed by server, with None for the client's default lookup.
    Yields the list of servers queried, in order.
    """

    queried: list[str | None] = []

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        server = command[2] if command[1] == "-h" else None
        queried.append(server)
        stdout, returncode = responses.get(server, ("", 0))
        stderr = "connect: Network is unreachable" if returncode else ""
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)

    with mock.patch("update_metadata.subprocess.run", side_effect=run):
        yield queried


class WhoisClientLookupTests(unittest.TestCase):
    def test_asks_other_registries_when_former_registry_has_no_object(self) -> None:
        with fake_whois(
            {None: (UNMANAGED_BLOCK, 0), "whois.arin.net": (ARIN_OBJECT, 0)}
        ) as queried:
            resolved = WhoisClient("whois", 5).lookup(199177)

        self.assertEqual(resolved["org_name"], "Ssmidge Technologies")
        self.assertEqual(queried, [None, "whois.arin.net"])

    def test_registry_fallback_follows_placeholder_referral(self) -> None:
        placeholder = """
ASNumber:       60809 - 61261
ASName:         RIPE-ASNBLOCK-60416
ResourceLink:  whois.ripe.net

OrgName:        RIPE Network Coordination Centre
Country:        NL
"""
        ripe_object = """
aut-num:        AS61218
as-name:        EXAMPLE-AS
org:            ORG-EX1-RIPE

organisation:   ORG-EX1-RIPE
org-name:       Example GmbH
country:        DE
"""

        with fake_whois(
            {
                None: ("% No entries found\n", 0),
                "whois.arin.net": (placeholder, 0),
                "whois.ripe.net": (ripe_object, 0),
            }
        ) as queried:
            resolved = WhoisClient("whois", 5).lookup(61218)

        self.assertEqual(resolved["as_name"], "EXAMPLE-AS")
        self.assertEqual(resolved["org_name"], "Example GmbH")
        self.assertEqual(queried, [None, "whois.arin.net", "whois.ripe.net"])

    def test_keeps_complete_answer_when_client_fails_afterwards(self) -> None:
        with fake_whois({None: (ARIN_OBJECT, 2)}) as queried:
            resolved = WhoisClient("whois", 5).lookup(199177)

        self.assertEqual(resolved["country"], "CA")
        self.assertEqual(queried, [None])

    def test_rejects_truncated_answer_from_failed_client(self) -> None:
        truncated = "ASNumber:       199177\nASName:         AS199177\n"

        with fake_whois({None: (truncated, 2)}) as queried:
            with self.assertRaisesRegex(LookupError, "Network is unreachable"):
                WhoisClient("whois", 5).lookup(199177)

        # A client that cannot connect must not fan out to every registry.
        self.assertEqual(queried, [None])


class FailingClient:
    def __init__(self) -> None:
        self.lookups: list[int] = []

    def lookup(self, asn: int) -> dict[str, str]:
        self.lookups.append(asn)
        raise LookupError("no matching object")


class RetryIntervalTests(unittest.TestCase):
    @staticmethod
    def failed_record(hours_ago: float) -> dict[str, dict[str, str]]:
        attempted_at = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        return {
            "64500": {
                "last_attempt": attempted_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "error": "LookupError: no matching object",
            }
        }

    def test_incremental_run_skips_recently_failed_lookup(self) -> None:
        client = FailingClient()
        metadata = self.failed_record(hours_ago=1)
        expected = {key: dict(value) for key, value in metadata.items()}

        result, failures = update_metadata(
            [64500], metadata, client, False, timedelta(hours=24)
        )

        self.assertEqual(client.lookups, [])
        self.assertEqual(failures, 0)
        self.assertEqual(result, expected)

    def test_incremental_run_retries_failed_lookup_after_interval(self) -> None:
        client = FailingClient()

        update_metadata(
            [64500], self.failed_record(hours_ago=25), client, False, timedelta(hours=24)
        )

        self.assertEqual(client.lookups, [64500])

    def test_refresh_ignores_retry_interval(self) -> None:
        client = FailingClient()

        update_metadata(
            [64500], self.failed_record(hours_ago=1), client, True, timedelta(hours=24)
        )

        self.assertEqual(client.lookups, [64500])


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
