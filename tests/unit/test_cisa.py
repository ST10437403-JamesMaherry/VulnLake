"""Unit tests for the CISA KEV source adapter."""

from pathlib import Path

import pytest

from vulnlake.ingestion.cisa import CisaKevClient

FIXTURE_PATH = Path("tests/fixtures/cisa_kev_sample.json")


def test_parse_valid_cisa_catalog() -> None:
    """A valid CISA fixture should satisfy the expected source contract."""

    payload = FIXTURE_PATH.read_bytes()

    catalog = CisaKevClient.parse(payload)

    assert catalog.catalog_version == "2026.09.09"
    assert catalog.count == 2
    assert len(catalog.vulnerabilities) == 2


def test_parse_rejects_invalid_json() -> None:
    """Malformed JSON must be rejected before Bronze persistence."""

    with pytest.raises(ValueError, match="not valid JSON"):
        CisaKevClient.parse(b"{ definitely-not-json }")


def test_parse_rejects_incorrect_declared_count() -> None:
    """The declared CISA count must match the delivered records."""

    payload = b"""
    {
        "title": "CISA Catalog",
        "catalogVersion": "1",
        "dateReleased": "2026-09-09T12:00:00Z",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2025-10001"
            }
        ]
    }
    """

    with pytest.raises(ValueError, match="record count"):
        CisaKevClient.parse(payload)


def test_parse_rejects_missing_cve_id() -> None:
    """Every vulnerability must identify its canonical CVE."""

    payload = b"""
    {
        "title": "CISA Catalog",
        "catalogVersion": "1",
        "dateReleased": "2026-09-09T12:00:00Z",
        "count": 1,
        "vulnerabilities": [
            {
                "vendorProject": "Example"
            }
        ]
    }
    """

    with pytest.raises(ValueError, match="cveID"):
        CisaKevClient.parse(payload)
