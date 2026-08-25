"""
Backend application configuration.

All settings are loaded from environment variables (or a .env file).
Never hard-code secrets or connection strings in source code.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings sourced from environment variables."""

    database_url: str
    environment: str = "development"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


def get_settings() -> Settings:
    """Return the application settings instance."""
    return Settings()  # type: ignore[call-arg]


settings: Settings = get_settings()
