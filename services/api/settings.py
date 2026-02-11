"""API service configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class ApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="API_")

    db_url: str = "postgresql://scanner:scanner@localhost:5432/scanner"
    host: str = "0.0.0.0"
    port: int = 8000
    default_page_limit: int = 50
    max_page_limit: int = 200
