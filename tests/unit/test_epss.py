"""Unit tests for the FIRST EPSS source adapter."""

import gzip
from pathlib import Path

import pytest

from vulnlake.ingestion.epss import EpssClient

# Deterministic local fixture containing synthetic EPSS records.
FIXTURE_PATH = Path("tests/fixtures/epss_scores_sample.csv")

# Reuse one valid metadata line across malformed-payload tests so each test
# changes only the behaviour it is specifically intended to validate.
VALID_METADATA_LINE = b"#model_version:v2026.06.15," b"score_date:2026-09-10T12:00:00Z"


def compress_lines(*lines: bytes) -> bytes:
    """Build deterministic gzip data from individual CSV source lines.

    ``mtime=0`` prevents gzip from embedding the current timestamp in the
    compressed header. Identical input therefore produces identical bytes,
    which is important because VulnLake fingerprints the raw source payload.
    """

    return gzip.compress(
        b"\n".join(lines),
        mtime=0,
    )


def compressed_fixture() -> bytes:
    """Return deterministic gzip bytes for the valid EPSS fixture."""

    return gzip.compress(
        FIXTURE_PATH.read_bytes(),
        mtime=0,
    )


def test_parse_valid_epss_feed() -> None:
    """A valid EPSS bulk feed should return source metadata and row count."""

    metadata = EpssClient.parse(compressed_fixture())

    assert metadata.model_version == "v2026.06.15"
    assert metadata.record_count == 3
    assert metadata.score_date.isoformat() == "2026-09-10T12:00:00+00:00"


def test_parse_rejects_invalid_gzip() -> None:
    """Non-gzip source content must never be accepted as EPSS Bronze data."""

    with pytest.raises(ValueError, match="gzip"):
        EpssClient.parse(b"this-is-not-gzip")


def test_parse_rejects_missing_required_column() -> None:
    """All documented EPSS analytical columns must be present."""

    payload = compress_lines(
        VALID_METADATA_LINE,
        b"cve,epss",
        b"CVE-2026-10001,0.5",
    )

    with pytest.raises(ValueError, match="percentile"):
        EpssClient.parse(payload)


def test_parse_rejects_epss_score_outside_probability_range() -> None:
    """EPSS probability values must remain inside the inclusive 0..1 range."""

    payload = compress_lines(
        VALID_METADATA_LINE,
        b"cve,epss,percentile",
        b"CVE-2026-10001,1.5,0.9",
    )

    with pytest.raises(ValueError, match="score outside 0..1"):
        EpssClient.parse(payload)


def test_parse_rejects_percentile_outside_probability_range() -> None:
    """EPSS percentile values must remain inside the inclusive 0..1 range."""

    payload = compress_lines(
        VALID_METADATA_LINE,
        b"cve,epss,percentile",
        b"CVE-2026-10001,0.5,1.1",
    )

    with pytest.raises(ValueError, match="percentile outside 0..1"):
        EpssClient.parse(payload)


def test_parse_rejects_invalid_cve_identifier() -> None:
    """Every EPSS record must identify a structurally valid CVE."""

    payload = compress_lines(
        VALID_METADATA_LINE,
        b"cve,epss,percentile",
        b"NOT-A-CVE,0.5,0.9",
    )

    with pytest.raises(ValueError, match="invalid CVE"):
        EpssClient.parse(payload)
