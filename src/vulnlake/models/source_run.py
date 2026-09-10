"""Operational metadata models for VulnLake source ingestion runs."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class RunStatus(StrEnum):
    """Supported ingestion run outcomes."""

    SUCCESS = "success"
    SKIPPED_DUPLICATE = "skipped_duplicate"
    FAILED = "failed"


class SourceRun(BaseModel):
    """Metadata describing one execution of a source ingestion pipeline."""

    # Unique identifier for this individual pipeline execution.
    run_id: str

    # Logical source identifier such as "cisa_kev".
    source: str

    # UTC timestamp at which VulnLake retrieved the source.
    fetched_at: datetime

    # Number of source records found in the payload.
    record_count: int

    # SHA-256 digest of the exact raw source bytes.
    checksum: str | None

    # VulnLake's expected source-contract version.
    schema_version: str

    # Outcome of this ingestion attempt.
    status: RunStatus

    # Source-specific release/version metadata.
    catalog_version: str | None = None
    source_released_at: datetime | None = None

    # Relative or absolute location of the persisted snapshot.
    snapshot_path: str | None = None

    # Optional operational context for failures/skips.
    message: str | None = None
