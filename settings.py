"""Centralised configuration for IOC Checker (API keys & globals). Requires Pydantic v2."""

from pydantic import Field
from pydantic import BaseSettings

class Settings(BaseSettings):
    VIRUSTOTAL_API_KEY: str | None = Field(default=None, env="VIRUSTOTAL_API_KEY")
    OTX_API_KEY: str | None = Field(default=None, env="OTX_API_KEY")
    ABUSEIPDB_API_KEY: str | None = Field(default=None, env="ABUSEIPDB_API_KEY")
    GREYNOISE_API_KEY: str | None = Field(default=None, env="GREYNOISE_API_KEY")
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")

    class Config:
        case_sensitive = False
        env_file       = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # Ignore extra environment variables

settings = Settings()

__all__ = ["settings", "Settings"] 