# pyright: reportMissingImports=false
"""Centralised configuration for IOC Checker (API keys & globals). Requires Pydantic v2."""

from pydantic import Field
from pydantic import BaseSettings

class Settings(BaseSettings):
    VIRUSTOTAL_API_KEY: str | None = Field(default=None, env="VIRUSTOTAL_API_KEY")
    OTX_API_KEY: str | None = Field(default=None, env="OTX_API_KEY")
    ABUSEIPDB_API_KEY: str | None = Field(default=None, env="ABUSEIPDB_API_KEY")
    GREYNOISE_API_KEY: str | None = Field(default=None, env="GREYNOISE_API_KEY")
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")

    # HTTP client defaults
    HTTP_DEFAULT_TIMEOUT: float = Field(default=15.0, env="HTTP_DEFAULT_TIMEOUT")
    HTTP_MAX_RETRIES: int = Field(default=3, env="HTTP_MAX_RETRIES")
    HTTP_BACKOFF_BASE: float = Field(default=0.5, env="HTTP_BACKOFF_BASE")
    HTTP_BACKOFF_CAP: float = Field(default=8.0, env="HTTP_BACKOFF_CAP")
    # Requests per second global rate limit. 0 disables limiting.
    HTTP_RPS_LIMIT: float = Field(default=0.0, env="HTTP_RPS_LIMIT")

    class Config:
        case_sensitive = False
        env_file       = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # Ignore extra environment variables

settings = Settings()

__all__ = ["settings", "Settings"] 