"""Application configuration for VulnLake."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application settings loaded from environment variables."""

    # Official CISA Known Exploited Vulnerabilities JSON feed.
    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    # Local lake root. Runtime lake contents are intentionally not committed.
    data_dir: Path = Path("data")

    # HTTP timeout used by source adapters.
    request_timeout_seconds: float = 30.0

    # Environment variables can override settings using the VULNLAKE_ prefix.
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
