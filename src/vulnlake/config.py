"""Central application configuration for VulnLake."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration shared across VulnLake pipeline components.

    Defaults are suitable for local development, while every setting can be
    overridden through environment variables prefixed with ``VULNLAKE_``.
    """

    # Official CISA Known Exploited Vulnerabilities JSON feed.
    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    # FIRST recommends the daily compressed CSV for complete EPSS bulk
    # ingestion. The URL redirects to the current dated score file.
    epss_scores_url: str = (
        "https://epss.empiricalsecurity.com/" "epss_scores-current.csv.gz"
    )

    # Root of the local medallion data lake.
    data_dir: Path = Path("data")

    # Maximum time allowed for one HTTP request.
    request_timeout_seconds: float = 30.0

    # Transient source failures receive a bounded number of attempts.
    http_max_attempts: int = 3

    # First exponential-backoff delay. Later delays grow as 1, 2, 4, ...
    http_backoff_base_seconds: float = 1.0

    # Environment variables can override configuration without modifying code.
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="VULNLAKE_",
        extra="ignore",
    )

    @property
    def bronze_dir(self) -> Path:
        """Return the configured Bronze-layer directory."""

        return self.data_dir / "bronze"


settings = Settings()
