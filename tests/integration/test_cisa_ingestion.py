"""Integration tests for the complete CISA KEV Bronze ingestion workflow."""

import json
from pathlib import Path

import pytest

from vulnlake.config import Settings
from vulnlake.ingestion.cisa import CisaKevClient, ingest_cisa_kev
from vulnlake.models.source_run import RunStatus
from vulnlake.utils.hashing import sha256_bytes

FIXTURE_PATH = Path("tests/fixtures/cisa_kev_sample.json")


def test_cisa_ingestion_is_idempotent_and_preserves_run_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identical CISA payloads should create one snapshot but two run records."""

    # Use deterministic fixture bytes rather than depending on CISA's live
    # endpoint. This makes the test reliable locally and in CI.
    payload = FIXTURE_PATH.read_bytes()

    # Replace only the network-fetch operation. Everything after fetching
    # executes through the real production ingestion code.
    monkeypatch.setattr(
        CisaKevClient,
        "fetch",
        lambda self: payload,
    )

    # tmp_path gives this test an isolated temporary data lake that pytest
    # removes automatically after the test completes.
    settings = Settings(
        data_dir=tmp_path / "data",
    )

    # The first run should create a new immutable Bronze snapshot.
    first_run = ingest_cisa_kev(settings)

    # The second run receives the exact same source bytes and should therefore
    # recognize that the content-addressed snapshot already exists.
    second_run = ingest_cisa_kev(settings)

    assert first_run.status == RunStatus.SUCCESS
    assert second_run.status == RunStatus.SKIPPED_DUPLICATE

    # Both executions should resolve to the same source snapshot.
    assert first_run.snapshot_path == second_run.snapshot_path

    snapshot_dir = tmp_path / "data" / "bronze" / "cisa_kev" / "snapshots"

    snapshots = list(snapshot_dir.glob("*.json"))

    # Idempotency means identical source data produces exactly one snapshot.
    assert len(snapshots) == 1

    # Bronze must preserve the exact original source bytes.
    assert snapshots[0].read_bytes() == payload

    # The content-addressed filename must equal the SHA-256 of the source.
    assert snapshots[0].stem == sha256_bytes(payload)

    run_dir = tmp_path / "data" / "bronze" / "_runs" / "cisa_kev"

    runs = list(run_dir.glob("*.json"))

    # Operational history is intentionally different from source history:
    # both executions are retained even though only one snapshot exists.
    assert len(runs) == 2


def test_invalid_cisa_payload_records_failed_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejected CISA payload should produce failed operational metadata."""

    malformed_payload = b"{this-is-not-valid-json}"

    # Simulate a source returning malformed content without making a real
    # network request.
    monkeypatch.setattr(
        CisaKevClient,
        "fetch",
        lambda self: malformed_payload,
    )

    settings = Settings(
        data_dir=tmp_path / "data",
    )

    # Invalid source data must still cause the pipeline itself to fail.
    with pytest.raises(ValueError, match="not valid JSON"):
        ingest_cisa_kev(settings)

    run_dir = tmp_path / "data" / "bronze" / "_runs" / "cisa_kev"

    runs = list(run_dir.glob("*.json"))

    # Even unsuccessful executions must leave an auditable run record.
    assert len(runs) == 1

    run_metadata = json.loads(runs[0].read_text())

    assert run_metadata["status"] == RunStatus.FAILED.value
    assert run_metadata["record_count"] == 0

    # The source bytes were received successfully, so we should still know
    # exactly which malformed payload caused the failure.
    assert run_metadata["checksum"] == sha256_bytes(malformed_payload)

    # Malformed source content must never be promoted into a valid Bronze
    # snapshot.
    snapshot_dir = tmp_path / "data" / "bronze" / "cisa_kev" / "snapshots"

    assert not snapshot_dir.exists()
