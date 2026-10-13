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
    """Describe one execution of an external-source ingestion pipeline.

    SourceRun is intentionally source-agnostic. CISA, EPSS, OSV and future
    adapters should expose their publisher-specific version information
    through the normalized ``source_version`` field.
    """

    # Unique identifier for this individual pipeline execution.
    run_id: str

    # Logical VulnLake source identifier, for example ``cisa_kev``.
    source: str

    # UTC timestamp at which VulnLake started retrieving the source.
    fetched_at: datetime

    # Number of source records accepted by the source-contract validator.
    record_count: int

    # SHA-256 digest of the exact original source bytes.
    checksum: str | None

    # Version of VulnLake's expected contract for this source.
    schema_version: str

    # Final outcome of the ingestion execution.
    status: RunStatus

    # Publisher-specific version mapped into one normalized field.
    # Examples:
    # - CISA catalog version
    # - EPSS model version
    source_version: str | None = None

    # Timestamp supplied by the source describing when its dataset was
    # released, generated or published.
    source_released_at: datetime | None = None

    # Persisted immutable Bronze snapshot location.
    snapshot_path: str | None = None

    # Human-readable operational context for success, duplicate or failure.
    message: str | None = None
