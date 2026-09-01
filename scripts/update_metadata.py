#!/usr/bin/env python3
"""Resolve requested autonomous systems through RDAP and update JSON metadata."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import requests

from country_metadata import country_metadata

DEFAULT_BOOTSTRAP_URL = "https://data.iana.org/rdap/asn.json"
REQUIRED_METADATA_FIELDS = (
    "as_name",
    "org_name",
    "country",
    "country_name",
    "flag",
    "last_success",
)


class RDAPClient:
    """Minimal ASN RDAP client using IANA's service bootstrap document."""

    def __init__(self, bootstrap_url: str, timeout: float) -> None:
        self.bootstrap_url = bootstrap_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/rdap+json, application/json",
                "User-Agent": "asn-metadata/1.0 (+https://github.com/TiekoetterNET/asn-metadata)",
            }
        )
        self._services: list[tuple[int, int, str]] | None = None

    def lookup(self, asn: int) -> dict[str, str]:
        endpoint = self._endpoint_for(asn)
        response = self.session.get(
            f"{endpoint.rstrip('/')}/autnum/{asn}", timeout=self.timeout
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError(f"RDAP response for AS{asn} was not a JSON object")

        code = _find_country_code(payload)
        code, country_name, flag = country_metadata(code)
        return {
            "as_name": _text(payload.get("name")) or _text(payload.get("handle")),
            "org_name": _find_org_name(payload),
            "country": code,
            "country_name": country_name,
            "flag": flag,
        }

    def _endpoint_for(self, asn: int) -> str:
        if self._services is None:
            self._services = self._load_services()

        for first, last, endpoint in self._services:
            if first <= asn <= last:
                return endpoint
        raise LookupError(f"IANA RDAP bootstrap has no service for AS{asn}")

    def _load_services(self) -> list[tuple[int, int, str]]:
        response = self.session.get(self.bootstrap_url, timeout=self.timeout)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("IANA RDAP bootstrap was not a JSON object")
        services: list[tuple[int, int, str]] = []

        raw_services = payload.get("services", [])
        if not isinstance(raw_services, list):
            raise ValueError("IANA RDAP bootstrap services were not a JSON array")
        for service in raw_services:
            if not isinstance(service, list) or len(service) != 2:
                continue
            ranges, endpoints = service
            if (
                not isinstance(ranges, list)
                or not isinstance(endpoints, list)
                or not endpoints
            ):
                continue
            endpoint = endpoints[0]
            if not isinstance(endpoint, str):
                continue
            for value in ranges:
                try:
                    first_text, separator, last_text = str(value).partition("-")
                    first = int(first_text)
                    last = int(last_text) if separator else first
                except ValueError:
                    continue
                services.append((first, last, endpoint))

        if not services:
            raise ValueError("IANA RDAP bootstrap did not contain any ASN services")
        return services


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        return " ".join(part.strip() for part in value if isinstance(part, str)).strip()
    return ""


def _vcard_properties(
    entity: dict[str, Any],
) -> Iterable[tuple[str, dict[str, Any], Any]]:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return
    for property_value in vcard[1]:
        if isinstance(property_value, list) and len(property_value) >= 4:
            parameters = property_value[1]
            if not isinstance(parameters, dict):
                parameters = {}
            yield str(property_value[0]).lower(), parameters, property_value[3]


def _ordered_entities(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw_entities = payload.get("entities", [])
    if not isinstance(raw_entities, list):
        return []
    entities = [item for item in raw_entities if isinstance(item, dict)]
    return sorted(entities, key=_entity_priority)


def _entity_priority(entity: dict[str, Any]) -> tuple[bool, bool, bool]:
    roles = entity.get("roles", [])
    if not isinstance(roles, list):
        roles = []
    handle = _text(entity.get("handle")).upper()
    properties = list(_vcard_properties(entity))
    is_org_entity = handle.startswith("ORG-") or any(
        name == "kind" and _text(value).lower() == "org"
        for name, _, value in properties
    )
    is_maintainer = handle.endswith("-MNT")
    return (
        "registrant" not in roles,
        not is_org_entity,
        is_maintainer,
    )


def _find_org_name(payload: dict[str, Any]) -> str:
    for entity in _ordered_entities(payload):
        properties = list(_vcard_properties(entity))
        for preferred_property in ("org", "fn"):
            for name, _, value in properties:
                if name == preferred_property and _text(value):
                    return _text(value)
    return ""


def _find_country_code(payload: dict[str, Any]) -> str:
    top_level = _text(payload.get("country"))
    if top_level:
        return pycountry_lookup(top_level)

    for entity in _ordered_entities(payload):
        entity_country = pycountry_lookup(_text(entity.get("country")))
        if entity_country:
            return entity_country

        for name, parameters, value in _vcard_properties(entity):
            if name != "adr" or not isinstance(value, list):
                continue
            parameter_country = pycountry_lookup(_text(parameters.get("cc")))
            if parameter_country:
                return parameter_country
            # RFC 6350: the seventh and final ADR component is the country.
            if len(value) >= 7 and _text(value[6]):
                country_value = _text(value[6])
                country = pycountry_lookup(country_value)
                if country:
                    return country

            # Some RIRs provide an empty structured ADR and put the complete
            # postal address in the label parameter. The country is normally
            # its final line, so check those lines from bottom to top.
            label = _text(parameters.get("label"))
            for line in reversed(label.splitlines()):
                country = pycountry_lookup(line.strip())
                if country:
                    return country
    return ""


def pycountry_lookup(value: str) -> str:
    """Resolve an alpha-2 code or country name without exposing pycountry here."""

    code, _, _ = country_metadata(value)
    if code:
        return code

    # Import lazily: most RDAP responses already contain a top-level code.
    import pycountry

    try:
        return pycountry.countries.lookup(value).alpha_2
    except LookupError:
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
    client: RDAPClient,
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
        except (requests.RequestException, LookupError, ValueError) as error:
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
    parser.add_argument("--bootstrap-url", default=DEFAULT_BOOTSTRAP_URL)
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
        client = RDAPClient(args.bootstrap_url, args.timeout)
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
