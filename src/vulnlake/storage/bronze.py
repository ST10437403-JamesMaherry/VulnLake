"""Immutable Bronze-layer persistence for VulnLake."""

import os
import tempfile
from pathlib import Path

from vulnlake.models.source_run import SourceRun


class BronzeStore:
    """Persist immutable raw snapshots and ingestion-run metadata."""

    def __init__(self, bronze_root: Path) -> None:
        """Initialize the Bronze store at the supplied lake path."""

        self.bronze_root = bronze_root

    @staticmethod
    def _normalize_suffix(suffix: str) -> str:
        """Validate and normalize a snapshot filename suffix.

        Examples:
            ``json`` becomes ``.json``
            ``.csv.gz`` remains ``.csv.gz``

        Path separators are rejected because callers should supply only a
        file-format suffix, never a path.
        """

        if not suffix:
            raise ValueError("Snapshot suffix must not be empty.")

        if "/" in suffix or "\\" in suffix:
            raise ValueError("Snapshot suffix must not contain path separators.")

        return suffix if suffix.startswith(".") else f".{suffix}"

    def snapshot_path(
        self,
        source: str,
        checksum: str,
        suffix: str = ".json",
    ) -> Path:
        """Return the content-addressed path for a raw source snapshot."""

        normalized_suffix = self._normalize_suffix(suffix)

        return (
            self.bronze_root / source / "snapshots" / f"{checksum}{normalized_suffix}"
        )

    def run_metadata_path(self, source: str, run_id: str) -> Path:
        """Return the JSON metadata path for one ingestion run."""

        return self.bronze_root / "_runs" / source / f"{run_id}.json"

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        """Write content atomically using a temporary file and replacement.

        The temporary file is created in the destination directory so the
        final ``os.replace`` occurs on the same filesystem.

        A partially written source file is therefore never exposed as a valid
        Bronze snapshot.
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
        suffix: str = ".json",
    ) -> tuple[Path, bool]:
        """Persist exact source bytes unless that content already exists.

        Args:
            source:
                Logical source identifier such as ``cisa_kev`` or ``epss``.

            checksum:
                SHA-256 digest calculated from the original source bytes.

            payload:
                Exact raw bytes received from the external source.

            suffix:
                File-format suffix retained by Bronze. Examples include
                ``.json`` and ``.csv.gz``.

        Returns:
            A tuple containing:
            - the immutable snapshot path
            - True when a new snapshot was created
            - False when identical content already existed
        """

        path = self.snapshot_path(
            source=source,
            checksum=checksum,
            suffix=suffix,
        )

        # Content-addressed persistence makes duplicate source snapshots a
        # no-op while leaving pipeline-run history independent.
        if path.exists():
            return path, False

        self._atomic_write(path, payload)

        return path, True

    def persist_run_metadata(self, run: SourceRun) -> Path:
        """Persist operational metadata for every ingestion execution."""

        path = self.run_metadata_path(run.source, run.run_id)

        # Pydantic provides consistent ISO-8601 datetime serialization.
        content = run.model_dump_json(indent=2).encode("utf-8")

        self._atomic_write(path, content)

        return path
