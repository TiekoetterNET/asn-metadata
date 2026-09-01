"""Helpers for enriching ISO 3166-1 country codes."""

from __future__ import annotations

import pycountry


def country_metadata(country_code: str | None) -> tuple[str, str, str]:
    """Return a normalized alpha-2 code, English name, and emoji flag.

    Unknown or absent country codes deliberately produce empty strings so an
    incomplete WHOIS response does not prevent the ASN itself from being saved.
    """

    if not country_code:
        return "", "", ""

    code = country_code.strip().upper()
    if len(code) != 2 or not code.isalpha():
        return "", "", ""

    # XK is commonly emitted by RIR data for Kosovo but is not an officially
    # assigned ISO 3166-1 code and therefore is not included in pycountry.
    if code == "XK":
        return code, "Kosovo", _country_flag(code)

    country = pycountry.countries.get(alpha_2=code)
    if country is None:
        return "", "", ""

    return code, country.name, _country_flag(code)


def _country_flag(code: str) -> str:
    """Convert a two-letter code to its Unicode regional-indicator flag."""

    return "".join(chr(ord(character) + 127397) for character in code)
