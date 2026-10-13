"""FIRST EPSS bulk-score ingestion adapter."""

import csv
import gzip
import io
import re
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel

from vulnlake.config import Settings
from vulnlake.ingestion.http import SourceHttpClient
from vulnlake.models.source_run import RunStatus, SourceRun
from vulnlake.storage.bronze import BronzeStore
from vulnlake.utils.hashing import sha256_bytes

# CVE identifiers consist of the CVE prefix, a four-digit year, and an
# identifier containing at least four digits.
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

# The EPSS daily CSV exposes these required analytical fields.
REQUIRED_COLUMNS = {"cve", "epss", "percentile"}


class EpssFeedMetadata(BaseModel):
    """Validated metadata extracted from one EPSS bulk score publication."""

    # EPSS model identifier published in the leading metadata comment.
    model_version: str

    # Timestamp describing when this score set was generated.
    score_date: datetime

    # Number of score rows successfully validated.
    record_count: int


class EpssClient:
    """Source adapter for the FIRST EPSS daily bulk score feed."""

    def __init__(
        self,
        url: str,
        http_client: SourceHttpClient,
    ) -> None:
        """Initialize the EPSS adapter using shared HTTP infrastructure."""

        self.url = url
        self.http_client = http_client

    def fetch(self) -> bytes:
        """Retrieve the exact gzip-compressed EPSS source payload."""

        return self.http_client.get_bytes(self.url)

    @staticmethod
    def _parse_metadata_line(line: str) -> tuple[str, datetime]:
        """Extract model version and score date from the EPSS metadata line.

        EPSS files begin with a comment containing source metadata, for
        example:

        #model_version:v2026.06.15,score_date:2026-07-28T12:00:27Z

        Parsing key/value pairs rather than hard-coding a version allows
        VulnLake to tolerate future EPSS model releases while still retaining
        source provenance.
        """

        if not line.startswith("#"):
            raise ValueError("EPSS payload is missing the metadata comment line.")

        metadata: dict[str, str] = {}

        # Remove the comment prefix and parse each comma-separated key/value
        # pair independently.
        for part in line.removeprefix("#").split(","):
            key, separator, value = part.partition(":")

            if not separator or not key.strip() or not value.strip():
                raise ValueError("EPSS metadata comment contains an invalid field.")

            metadata[key.strip()] = value.strip()

        model_version = metadata.get("model_version")
        score_date_raw = metadata.get("score_date")

        if not model_version:
            raise ValueError("EPSS metadata is missing model_version.")

        if not score_date_raw:
            raise ValueError("EPSS metadata is missing score_date.")

        try:
            # Python 3.12+ understands the ISO-8601 ``Z`` suffix directly
            # and produces a timezone-aware UTC datetime.
            score_date = datetime.fromisoformat(score_date_raw)
        except ValueError as exc:
            raise ValueError(
                "EPSS score_date is not a valid ISO-8601 timestamp."
            ) from exc

        # Source publication times must be timezone-aware so downstream
        # freshness comparisons remain globally consistent.
        if score_date.tzinfo is None:
            raise ValueError("EPSS score_date must include timezone information.")

        return model_version, score_date

    @staticmethod
    def parse(payload: bytes) -> EpssFeedMetadata:
        """Validate a gzip-compressed EPSS bulk score payload.

        Validation operates on a decompressed copy of the source while the
        original compressed bytes remain unchanged. Bronze therefore retains
        exactly what FIRST supplied.
        """

        # EPSS bulk files are distributed as gzip-compressed CSV data.
        try:
            decompressed = gzip.decompress(payload)
        except (gzip.BadGzipFile, EOFError, OSError) as exc:
            raise ValueError("EPSS payload is not valid gzip-compressed data.") from exc

        # CSV parsing requires the decompressed bytes to contain UTF-8 text.
        try:
            text = decompressed.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("EPSS payload is not valid UTF-8 text.") from exc

        stream = io.StringIO(text)

        # The first line contains EPSS publication metadata rather than CSV
        # column headings.
        metadata_line = stream.readline().strip()

        model_version, score_date = EpssClient._parse_metadata_line(metadata_line)

        # DictReader begins at the next line, which must contain the CSV
        # header.
        reader = csv.DictReader(stream)

        if reader.fieldnames is None:
            raise ValueError("EPSS payload is missing the CSV header.")

        actual_columns = {
            column.strip() for column in reader.fieldnames if column is not None
        }

        missing_columns = REQUIRED_COLUMNS - actual_columns

        if missing_columns:
            missing = ", ".join(sorted(missing_columns))

            raise ValueError(f"EPSS payload is missing required columns: {missing}.")

        record_count = 0

        # Validate every source record before allowing the payload into the
        # valid Bronze snapshot namespace.
        for row_number, row in enumerate(reader, start=1):
            cve = (row.get("cve") or "").strip()
            epss_raw = (row.get("epss") or "").strip()
            percentile_raw = (row.get("percentile") or "").strip()

            # Silver will later canonicalize and model CVEs. Bronze validation
            # only ensures the source provides structurally valid identities.
            if not CVE_PATTERN.fullmatch(cve):
                raise ValueError(f"EPSS row {row_number} contains an invalid CVE ID.")

            try:
                epss_score = float(epss_raw)
            except ValueError as exc:
                raise ValueError(
                    f"EPSS row {row_number} contains " "a non-numeric EPSS score."
                ) from exc

            try:
                percentile = float(percentile_raw)
            except ValueError as exc:
                raise ValueError(
                    f"EPSS row {row_number} contains " "a non-numeric percentile."
                ) from exc

            # EPSS represents exploitation probability as a value from zero
            # through one inclusive.
            if not 0.0 <= epss_score <= 1.0:
                raise ValueError(
                    f"EPSS row {row_number} contains " "a score outside 0..1."
                )

            # Percentile is represented using the same normalized range.
            if not 0.0 <= percentile <= 1.0:
                raise ValueError(
                    f"EPSS row {row_number} contains " "a percentile outside 0..1."
                )

            record_count += 1

        if record_count == 0:
            raise ValueError("EPSS payload contains no score records.")

        return EpssFeedMetadata(
            model_version=model_version,
            score_date=score_date,
            record_count=record_count,
        )


def ingest_epss(settings: Settings) -> SourceRun:
    """Execute the FIRST EPSS to Bronze ingestion pipeline.

    The exact gzip-compressed source bytes are fingerprinted and persisted
    unchanged. Parsing and decompression are used only to validate the source
    contract and extract operational metadata.
    """

    source = "epss"
    schema_version = "epss-v1"
    run_id = str(uuid4())

    # Pipeline execution timestamps use UTC regardless of the machine or
    # hosted runner executing VulnLake.
    fetched_at = datetime.now(UTC)

    # Storage exists before source processing begins so source failures can
    # still leave an auditable operational run record.
    bronze_store = BronzeStore(settings.bronze_dir)

    # EPSS shares the same bounded retry, timeout and redirect behaviour as
    # every other HTTP-backed VulnLake source.
    http_client = SourceHttpClient(
        timeout_seconds=settings.request_timeout_seconds,
        max_attempts=settings.http_max_attempts,
        backoff_base_seconds=settings.http_backoff_base_seconds,
    )

    client = EpssClient(
        url=settings.epss_scores_url,
        http_client=http_client,
    )

    # The checksum cannot be known until source bytes have been received.
    checksum: str | None = None

    try:
        # Fetch and retain the exact gzip-compressed representation returned by
        # FIRST.
        payload = client.fetch()

        # Fingerprint the raw compressed bytes before any parsing or
        # transformation occurs.
        checksum = sha256_bytes(payload)

        # Decompression and CSV parsing occur only for contract validation.
        metadata = client.parse(payload)

        # EPSS is retained in its original .csv.gz representation rather than
        # being converted into JSON at the Bronze boundary.
        snapshot_path, was_created = bronze_store.persist_snapshot(
            source=source,
            checksum=checksum,
            payload=payload,
            suffix=".csv.gz",
        )

        status = RunStatus.SUCCESS if was_created else RunStatus.SKIPPED_DUPLICATE

        # SourceRun normalizes source-specific publication metadata so CISA,
        # EPSS and future providers share one operational lineage model.
        run = SourceRun(
            run_id=run_id,
            source=source,
            fetched_at=fetched_at,
            record_count=metadata.record_count,
            checksum=checksum,
            schema_version=schema_version,
            status=status,
            source_version=metadata.model_version,
            source_released_at=metadata.score_date,
            snapshot_path=str(snapshot_path),
            message=(
                "New immutable Bronze snapshot created."
                if was_created
                else "Identical source snapshot already exists."
            ),
        )

        # Run history is independent from source snapshot history. Duplicate
        # source content therefore still receives a separate execution record.
        bronze_store.persist_run_metadata(run)

        return run

    except Exception as exc:
        # Invalid or unavailable source data must not become a valid Bronze
        # snapshot, but the failed execution should remain observable.
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

        # Preserve the original error signal so CLI execution, CI and future
        # orchestration correctly fail rather than silently continuing.
        raise
