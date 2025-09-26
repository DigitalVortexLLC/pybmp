from pydantic_settings import BaseSettings
from pydantic import Field, field_validator, ConfigDict
from typing import Optional, Annotated
import os


class Settings(BaseSettings):
    # Database settings
    db_host: str = Field(default="localhost")
    db_port: int = Field(default=5432)
    db_name: str = Field(default="bmp_collector")
    db_user: str = Field(default="bmp_user")
    db_password: str
    db_pool_size: int = Field(default=20)
    db_max_overflow: int = Field(default=40)

    # BMP Server settings
    bmp_listen_host: str = Field(default="0.0.0.0")
    bmp_listen_port: int = Field(default=11019)
    bmp_buffer_size: int = Field(default=65536)
    bmp_max_connections: int = Field(default=100)

    # Data retention settings
    data_retention_days: int = Field(default=90)
    cleanup_interval_hours: int = Field(default=24)

    # Logging settings
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # Metrics settings
    metrics_enabled: bool = Field(default=True)
    metrics_port: int = Field(default=9090)

    # Processing settings
    batch_size: int = Field(default=1000)
    batch_timeout_seconds: int = Field(default=5)
    worker_threads: int = Field(default=4)

    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v):
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}")
        return v.upper()

    @property
    def database_url(self) -> str:
        """Generate PostgreSQL connection URL."""
        return f"postgresql+asyncpg://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def sync_database_url(self) -> str:
        """Generate synchronous PostgreSQL connection URL."""
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"


def get_settings() -> Settings:
    """Get application settings."""
    return Settings()
