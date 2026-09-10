"""Tests for immutable Bronze-layer persistence."""

from pathlib import Path

from vulnlake.storage.bronze import BronzeStore
from vulnlake.utils.hashing import sha256_bytes


def test_identical_payload_does_not_create_duplicate_snapshot(
    tmp_path: Path,
) -> None:
    """Writing identical source content twice should reuse one snapshot."""

    store = BronzeStore(tmp_path / "bronze")

    payload = b'{"example": "immutable source data"}'
    checksum = sha256_bytes(payload)

    first_path, first_created = store.persist_snapshot(
        source="cisa_kev",
        checksum=checksum,
        payload=payload,
    )

    second_path, second_created = store.persist_snapshot(
        source="cisa_kev",
        checksum=checksum,
        payload=payload,
    )

    assert first_created is True
    assert second_created is False

    assert first_path == second_path
    assert first_path.read_bytes() == payload

    # Exactly one immutable raw snapshot should exist.
    snapshots = list((tmp_path / "bronze" / "cisa_kev" / "snapshots").glob("*.json"))

    assert len(snapshots) == 1
