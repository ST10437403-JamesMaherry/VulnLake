"""Integration tests for the complete FIRST EPSS Bronze ingestion workflow."""

import gzip
import json
from pathlib import Path

import pytest

from vulnlake.config import Settings
from vulnlake.ingestion.epss import EpssClient, ingest_epss
from vulnlake.models.source_run import RunStatus
from vulnlake.utils.hashing import sha256_bytes

# This fixture contains synthetic EPSS records used only for deterministic
# testing. Integration tests must never depend on the availability or current
# contents of FIRST's live EPSS service.
FIXTURE_PATH = Path("tests/fixtures/epss_scores_sample.csv")


def compressed_fixture() -> bytes:
    """Return deterministic gzip bytes for the synthetic EPSS fixture.

    Gzip files can embed a creation timestamp. Setting ``mtime=0`` guarantees
    that identical fixture input produces identical compressed bytes and,
    therefore, the same SHA-256 checksum on every test execution.
    """

    return gzip.compress(
        FIXTURE_PATH.read_bytes(),
        mtime=0,
    )


def test_epss_ingestion_is_idempotent_and_preserves_run_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identical EPSS input should create one snapshot but two run records."""

    payload = compressed_fixture()

    # Replace only the external network boundary.
    #
    # Parsing, validation, hashing, Bronze persistence, duplicate detection
    # and operational metadata all continue through the real production code.
    monkeypatch.setattr(
        EpssClient,
        "fetch",
        lambda self: payload,
    )

    # Give the test its own temporary lake so automated tests never modify the
    # developer's real data/ directory.
    settings = Settings(
        data_dir=tmp_path / "data",
    )

    # First execution should observe a new source state.
    first_run = ingest_epss(settings)

    # The second execution receives byte-for-byte identical source content.
    second_run = ingest_epss(settings)

    assert first_run.status == RunStatus.SUCCESS
    assert second_run.status == RunStatus.SKIPPED_DUPLICATE

    # Both executions must resolve to the exact same immutable source object.
    assert first_run.snapshot_path == second_run.snapshot_path

    # Verify that EPSS-specific publisher metadata was normalized into the
    # generic SourceRun model correctly.
    assert first_run.source == "epss"
    assert first_run.source_version == "v2026.06.15"
    assert first_run.record_count == 3
    assert first_run.source_released_at is not None
    assert first_run.source_released_at.isoformat() == ("2026-09-10T12:00:00+00:00")

    snapshot_dir = tmp_path / "data" / "bronze" / "epss" / "snapshots"

    snapshots = list(snapshot_dir.glob("*.csv.gz"))

    # Two identical executions must not create two copies of the same source.
    assert len(snapshots) == 1

    snapshot = snapshots[0]
    expected_checksum = sha256_bytes(payload)

    # Bronze must preserve the exact original compressed source bytes.
    assert snapshot.read_bytes() == payload

    # Content-addressed storage means the filename itself represents the
    # SHA-256 identity of the raw source.
    assert snapshot.name == f"{expected_checksum}.csv.gz"

    run_dir = tmp_path / "data" / "bronze" / "_runs" / "epss"

    run_files = list(run_dir.glob("*.json"))

    # Source-state history and pipeline-execution history are deliberately
    # separate. One source state was seen during two pipeline executions.
    assert len(run_files) == 2

    run_metadata = [
        json.loads(run_file.read_text(encoding="utf-8")) for run_file in run_files
    ]

    statuses = {run["status"] for run in run_metadata}

    assert statuses == {
        RunStatus.SUCCESS.value,
        RunStatus.SKIPPED_DUPLICATE.value,
    }


def test_invalid_epss_payload_records_failed_run_without_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed EPSS data should be audited but never accepted into Bronze."""

    malformed_payload = b"this-is-not-valid-gzip-data"

    # Simulate FIRST returning malformed source bytes without making a real
    # HTTP request.
    monkeypatch.setattr(
        EpssClient,
        "fetch",
        lambda self: malformed_payload,
    )

    settings = Settings(
        data_dir=tmp_path / "data",
    )

    # The ingestion must still fail visibly to the caller.
    with pytest.raises(ValueError, match="gzip"):
        ingest_epss(settings)

    run_dir = tmp_path / "data" / "bronze" / "_runs" / "epss"

    run_files = list(run_dir.glob("*.json"))

    # Failed pipeline executions must remain observable.
    assert len(run_files) == 1

    run_metadata = json.loads(run_files[0].read_text(encoding="utf-8"))

    assert run_metadata["source"] == "epss"
    assert run_metadata["status"] == RunStatus.FAILED.value
    assert run_metadata["record_count"] == 0

    # The source bytes were successfully received before validation failed,
    # so their identity remains useful for debugging and forensic evidence.
    assert run_metadata["checksum"] == sha256_bytes(malformed_payload)

    assert "ValueError" in run_metadata["message"]

    snapshot_dir = tmp_path / "data" / "bronze" / "epss" / "snapshots"

    # Rejected input must never appear beside accepted Bronze snapshots.
    assert not snapshot_dir.exists()
