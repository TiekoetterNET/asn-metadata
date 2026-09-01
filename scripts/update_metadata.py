#!/usr/bin/env python3
"""Resolve requested autonomous systems through WHOIS and update JSON metadata."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from country_metadata import country_metadata

REQUIRED_METADATA_FIELDS = (
    "as_name",
    "org_name",
    "country",
    "country_name",
    "flag",
    "source",
    "last_success",
)


WhoisBlock = dict[str, list[str]]
WHOIS_ATTRIBUTE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.*?)\s*$")


class WhoisClient:
    """Resolve AS metadata with the system WHOIS client and RIR referrals."""

    def __init__(self, command: str, timeout: float) -> None:
        self.command = command
        self.timeout = timeout

    def lookup(self, asn: int) -> dict[str, str]:
        response = self._run([f"AS{asn}"])
        try:
            return parse_whois_response(asn, response)
        except ValueError as initial_error:
            # Some WHOIS clients do not follow referral links unless they use
            # the whois:// scheme. ARIN occasionally returns a bare WHOIS host
            # in ResourceLink, so follow those registry hosts explicitly.
            for server in reversed(_find_referral_servers(response)):
                referred_response = self._run(["-h", server, f"AS{asn}"])
                try:
                    return parse_whois_response(asn, referred_response)
                except ValueError:
                    continue
            raise initial_error

    def _run(self, arguments: list[str]) -> str:
        try:
            result = subprocess.run(
                [self.command, *arguments],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError as error:
            raise LookupError(f"WHOIS command not found: {self.command}") from error
        except subprocess.TimeoutExpired as error:
            raise LookupError(f"WHOIS lookup timed out after {self.timeout:g}s") from error

        if result.returncode != 0:
            detail = result.stderr.strip() or f"exit status {result.returncode}"
            raise LookupError(f"WHOIS lookup failed: {detail}")
        return result.stdout


def parse_whois_response(asn: int, response: str) -> dict[str, str]:
    """Parse explicit ASN and organization attributes from referral output."""

    blocks = _parse_whois_blocks(response)
    asn_index = _find_asn_block(blocks, asn)
    if asn_index is None:
        raise ValueError(f"WHOIS response did not contain an exact AS{asn} object")

    asn_block = blocks[asn_index]
    org_block = _find_org_block(blocks, asn_index, asn_block)

    as_name = _first_attribute(asn_block, "as-name", "asname", "owner")
    if not as_name:
        as_name = f"AS{asn}"

    org_name = ""
    country_code = ""
    if org_block is not None:
        org_name = _first_attribute(org_block, "org-name", "orgname", "owner")
        country_code = _first_attribute(org_block, "country")

    if not org_name:
        org_name = _first_attribute(asn_block, "owner", "org-name", "orgname")
    if not country_code:
        country_code = _first_attribute(asn_block, "country")

    code, country_name, flag = country_metadata(country_code)
    return {
        "as_name": as_name,
        "org_name": org_name,
        "country": code,
        "country_name": country_name,
        "flag": flag,
        "source": "whois",
    }


def _parse_whois_blocks(response: str) -> list[WhoisBlock]:
    blocks: list[WhoisBlock] = []
    current: WhoisBlock = {}

    for line in response.splitlines():
        if not line.strip():
            if current:
                blocks.append(current)
                current = {}
            continue
        match = WHOIS_ATTRIBUTE.match(line)
        if match is None:
            continue
        name, value = match.groups()
        current.setdefault(name.lower(), []).append(value.strip())

    if current:
        blocks.append(current)
    return blocks


def _find_referral_servers(response: str) -> list[str]:
    servers: list[str] = []
    for block in _parse_whois_blocks(response):
        for attribute in ("whois", "referralserver", "resourcelink"):
            for value in block.get(attribute, []):
                candidate = value.strip()
                if candidate.lower().startswith("whois://"):
                    candidate = candidate[8:].split("/", 1)[0]
                if not candidate.lower().startswith("whois."):
                    continue
                if not re.fullmatch(r"[A-Za-z0-9.-]+", candidate):
                    continue
                if candidate not in servers:
                    servers.append(candidate)
    return servers


def _find_asn_block(blocks: list[WhoisBlock], asn: int) -> int | None:
    for index, block in enumerate(blocks):
        values = [*block.get("aut-num", []), *block.get("asnumber", [])]
        if any(_is_exact_asn(value, asn) for value in values):
            return index
    return None


def _is_exact_asn(value: str, asn: int) -> bool:
    match = re.fullmatch(r"(?:AS)?0*([0-9]+)", value.strip(), re.IGNORECASE)
    return match is not None and int(match.group(1)) == asn


def _find_org_block(
    blocks: list[WhoisBlock], asn_index: int, asn_block: WhoisBlock
) -> WhoisBlock | None:
    org_reference = _first_attribute(asn_block, "org")
    if org_reference:
        for block in blocks[asn_index + 1 :]:
            organisation = _first_attribute(block, "organisation")
            if organisation.casefold() == org_reference.casefold():
                return block

    # ARIN returns an adjacent OrgName object without an explicit reference in
    # the ASN object. Restrict this fallback to objects following the exact ASN.
    for block in blocks[asn_index + 1 :]:
        if "orgname" in block:
            return block
    return None


def _first_attribute(block: WhoisBlock, *names: str) -> str:
    for name in names:
        for value in block.get(name, []):
            if value:
                return value
    return ""


def normalize_requested_asns(payload: Any, source: str) -> list[int]:
    if not isinstance(payload, list):
        raise ValueError(f"{source} must contain a JSON array")

    asns: set[int] = set()
    for value in payload:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid ASN value: {value!r}")
        asn = value
        if not 1 <= asn <= 4_294_967_295:
            raise ValueError(f"invalid ASN value: {value!r}")
        asns.add(asn)
    return sorted(asns)


def load_requested_asns(path: Path) -> list[int]:
    return normalize_requested_asns(_load_json(path), str(path))


def fetch_requested_asns(url: str, timeout: float) -> list[int]:
    """Fetch and validate the requested ASN list without modifying the fixture."""

    if not url.strip():
        raise ValueError("--requested-url must not be empty")

    response = requests.get(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": (
                "asn-metadata/1.0 "
                "(+https://github.com/TiekoetterNET/asn-metadata)"
            ),
        },
        timeout=timeout,
    )
    response.raise_for_status()
    return normalize_requested_asns(response.json(), url)


def load_metadata(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    payload = _load_json(path)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    if not all(
        isinstance(key, str) and isinstance(value, dict)
        for key, value in payload.items()
    ):
        raise ValueError(f"{path} must map ASN strings to metadata objects")
    if any(
        not key.isdigit()
        or str(int(key)) != key
        or not 1 <= int(key) <= 4_294_967_295
        for key in payload
    ):
        raise ValueError(f"{path} contains an invalid ASN key")
    return payload


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _needs_lookup(record: dict[str, Any] | None) -> bool:
    return not record or any(field not in record for field in REQUIRED_METADATA_FIELDS)


def update_metadata(
    requested_asns: list[int],
    metadata: dict[str, dict[str, Any]],
    client: WhoisClient,
    refresh_all: bool,
) -> tuple[dict[str, dict[str, Any]], int]:
    if refresh_all:
        targets = sorted({*requested_asns, *(int(key) for key in metadata)})
    else:
        targets = [asn for asn in requested_asns if _needs_lookup(metadata.get(str(asn)))]

    failures = 0
    for asn in targets:
        key = str(asn)
        previous = metadata.get(key, {})
        attempted_at = _timestamp()
        try:
            resolved = client.lookup(asn)
        except (LookupError, ValueError) as error:
            failures += 1
            metadata[key] = {
                **previous,
                "last_attempt": attempted_at,
                "error": f"{type(error).__name__}: {error}",
            }
            print(f"AS{asn}: lookup failed: {error}", file=sys.stderr)
            continue

        metadata[key] = {
            **resolved,
            "last_attempt": attempted_at,
            "last_success": attempted_at,
        }
        print(f"AS{asn}: updated")

    return dict(sorted(metadata.items(), key=lambda item: int(item[0]))), failures


def write_metadata(path: Path, metadata: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(f"{path.suffix}.tmp")
    with temporary_path.open("w", encoding="utf-8") as file:
        json.dump(metadata, file, ensure_ascii=False, indent=2)
        file.write("\n")
    temporary_path.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requested", type=Path, default=Path("data/requested-asns.json"))
    parser.add_argument(
        "--requested-url",
        help="fetch requested ASNs from this URL instead of the local fixture",
    )
    parser.add_argument("--metadata", type=Path, default=Path("data/asn-metadata.json"))
    parser.add_argument(
        "--refresh-all",
        action="store_true",
        help="refresh every requested and previously known ASN",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--whois-command",
        default="whois",
        help="WHOIS executable to use (default: whois)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        requested_asns = (
            fetch_requested_asns(args.requested_url, args.timeout)
            if args.requested_url is not None
            else load_requested_asns(args.requested)
        )
        metadata = load_metadata(args.metadata)
        client = WhoisClient(args.whois_command, args.timeout)
        metadata, failures = update_metadata(
            requested_asns, metadata, client, args.refresh_all
        )
        write_metadata(args.metadata, metadata)
    except (
        OSError,
        json.JSONDecodeError,
        requests.RequestException,
        ValueError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if failures:
        print(f"Completed with {failures} failed lookup(s); previous data was retained.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
