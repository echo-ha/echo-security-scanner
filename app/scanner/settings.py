"""Scanner service configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class ScannerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANNER_")

    db_url: str = "sqlite:///scanner.db"
    scan_interval_seconds: int = 900      # 15 min rescan interval
    stale_timeout_seconds: int = 600      # 10 min stale timeout
    failed_retry_seconds: int = 300       # 5 min backoff before retrying failed images
    batch_size: int = 5
