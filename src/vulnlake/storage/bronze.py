"""Immutable Bronze-layer persistence for VulnLake."""

import os
import tempfile
from pathlib import Path

from vulnlake.models.source_run import SourceRun


class BronzeStore:
    """Persist immutable raw snapshots and ingestion-run metadata."""

    def __init__(self, bronze_root: Path) -> None:
        """Initialize the Bronze store."""

        self.bronze_root = bronze_root

    def snapshot_path(self, source: str, checksum: str) -> Path:
        """Return the content-addressed path for a raw source snapshot."""

        return self.bronze_root / source / "snapshots" / f"{checksum}.json"

    def run_metadata_path(self, source: str, run_id: str) -> Path:
        """Return the metadata path for an ingestion run."""

        return self.bronze_root / "_runs" / source / f"{run_id}.json"

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        """Write content atomically using a temporary file then replacement.

        Writing to a temporary file first prevents a partially written
        Bronze object from appearing as a valid snapshot if the process
        fails during the write.
        """

        path.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            delete=False,
        ) as temp_file:
            temp_file.write(content)
            temporary_path = Path(temp_file.name)

        os.replace(temporary_path, path)

    def persist_snapshot(
        self,
        source: str,
        checksum: str,
        payload: bytes,
    ) -> tuple[Path, bool]:
        """Persist a raw snapshot unless that exact content already exists.

        Returns:
            A tuple containing:
            - snapshot path
            - True if a new file was created, otherwise False
        """

        path = self.snapshot_path(source, checksum)

        # Content-addressed storage provides natural idempotency.
        if path.exists():
            return path, False

        self._atomic_write(path, payload)

        return path, True

    def persist_run_metadata(self, run: SourceRun) -> Path:
        """Persist metadata for every pipeline execution."""

        path = self.run_metadata_path(run.source, run.run_id)

        # Serialize through Pydantic to keep datetime formatting consistent.
        content = run.model_dump_json(indent=2).encode("utf-8")

        self._atomic_write(path, content)

        return path
