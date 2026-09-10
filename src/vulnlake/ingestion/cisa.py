"""CISA Known Exploited Vulnerabilities ingestion adapter."""

import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field, ValidationError

from vulnlake.config import Settings
from vulnlake.models.source_run import RunStatus, SourceRun
from vulnlake.storage.bronze import BronzeStore
from vulnlake.utils.hashing import sha256_bytes


class CisaKevCatalog(BaseModel):
    """Minimum source contract required from the CISA KEV catalog."""

    # Source catalogue metadata.
    title: str
    catalog_version: str = Field(alias="catalogVersion")
    date_released: datetime = Field(alias="dateReleased")
    count: int

    # Bronze keeps the actual records source-shaped and unmodified.
    vulnerabilities: list[dict[str, Any]]


class CisaKevClient:
    """HTTP client and source validator for the CISA KEV feed."""

    def __init__(self, url: str, timeout_seconds: float = 30.0) -> None:
        """Initialize the CISA adapter."""

        self.url = url
        self.timeout_seconds = timeout_seconds

    def fetch(self) -> bytes:
        """Retrieve the exact raw CISA KEV payload."""

        with httpx.Client(
            timeout=self.timeout_seconds,
            follow_redirects=True,
        ) as client:
            response = client.get(self.url)

            # Any non-success response should stop ingestion immediately.
            response.raise_for_status()

            return response.content

    @staticmethod
    def parse(payload: bytes) -> CisaKevCatalog:
        """Validate the minimum CISA source contract.

        The parsed object is used only for validation and metadata extraction.
        The original payload remains unchanged when written to Bronze.
        """

        try:
            raw_document = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("CISA KEV payload is not valid JSON.") from exc

        try:
            catalog = CisaKevCatalog.model_validate(raw_document)
        except ValidationError as exc:
            raise ValueError(
                "CISA KEV payload does not match the expected source contract."
            ) from exc

        # The catalogue's declared count should match the records delivered.
        if catalog.count != len(catalog.vulnerabilities):
            raise ValueError(
                "CISA KEV record count does not match vulnerabilities array."
            )

        # Every KEV record must identify the vulnerability it represents.
        for vulnerability in catalog.vulnerabilities:
            cve_id = vulnerability.get("cveID")

            if not isinstance(cve_id, str) or not cve_id.strip():
                raise ValueError("CISA KEV vulnerability is missing a valid cveID.")

        return catalog


def ingest_cisa_kev(settings: Settings) -> SourceRun:
    """Execute the complete CISA KEV to Bronze ingestion pipeline.

    Every execution receives a unique run identifier. Successful runs create
    or reuse an immutable Bronze snapshot, while failed runs are also recorded
    so that ingestion failures remain observable and auditable.
    """

    source = "cisa_kev"
    schema_version = "cisa-kev-v1"
    run_id = str(uuid4())
    fetched_at = datetime.now(UTC)

    # Create storage before ingestion starts so that failures can also be
    # recorded as pipeline-run metadata.
    bronze_store = BronzeStore(settings.bronze_dir)

    # Configure the source-specific HTTP adapter.
    client = CisaKevClient(
        url=settings.cisa_kev_url,
        timeout_seconds=settings.request_timeout_seconds,
    )

    # These values begin empty because an HTTP or parsing failure may occur
    # before all source metadata can be derived.
    checksum: str | None = None

    try:
        # Preserve the exact bytes returned by CISA. Bronze must contain the
        # unchanged source representation rather than a transformed version.
        payload = client.fetch()

        # Hash the original bytes immediately. Even if schema validation later
        # fails, the failed source payload still has a traceable fingerprint.
        checksum = sha256_bytes(payload)

        # Validate the expected source contract and extract catalog metadata.
        catalog = client.parse(payload)

        # Content-addressed persistence makes ingestion idempotent: identical
        # source bytes resolve to the same snapshot filename.
        snapshot_path, was_created = bronze_store.persist_snapshot(
            source=source,
            checksum=checksum,
            payload=payload,
        )

        status = RunStatus.SUCCESS if was_created else RunStatus.SKIPPED_DUPLICATE

        # Record the successful or duplicate ingestion attempt independently
        # from the immutable source snapshot.
        run = SourceRun(
            run_id=run_id,
            source=source,
            fetched_at=fetched_at,
            record_count=catalog.count,
            checksum=checksum,
            schema_version=schema_version,
            status=status,
            catalog_version=catalog.catalog_version,
            source_released_at=catalog.date_released,
            snapshot_path=str(snapshot_path),
            message=(
                "New immutable Bronze snapshot created."
                if was_created
                else "Identical source snapshot already exists."
            ),
        )

        bronze_store.persist_run_metadata(run)

        return run

    except Exception as exc:
        # A failed ingestion must still leave operational evidence behind.
        # We deliberately do not persist a malformed source as a valid Bronze
        # snapshot, but its checksum is retained when one could be calculated.
        failed_run = SourceRun(
            run_id=run_id,
            source=source,
            fetched_at=fetched_at,
            record_count=0,
            checksum=checksum,
            schema_version=schema_version,
            status=RunStatus.FAILED,
            message=f"{type(exc).__name__}: {exc}",
        )

        bronze_store.persist_run_metadata(failed_run)

        # Re-raise the original exception so callers, CI, and scheduled jobs
        # still receive a non-successful execution result.
        raise
