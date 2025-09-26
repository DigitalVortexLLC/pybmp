"""Unit tests for configuration management."""
import pytest
import os
from unittest.mock import patch, mock_open
from pydantic import ValidationError

from src.utils.config import Settings, get_settings


class TestSettings:
    """Test Settings configuration class."""

    @pytest.mark.unit
    def test_default_settings(self):
        """Test default configuration values."""
        with patch.dict(os.environ, {}, clear=True):
            # Mock required password field
            with patch.dict(os.environ, {"DB_PASSWORD": "test_password"}):
                settings = Settings()

                # Database defaults
                assert settings.db_host == "localhost"
                assert settings.db_port == 5432
                assert settings.db_name == "bmp_collector"
                assert settings.db_user == "bmp_user"
                assert settings.db_password == "test_password"
                assert settings.db_pool_size == 20

                # BMP server defaults
                assert settings.bmp_listen_host == "0.0.0.0"
                assert settings.bmp_listen_port == 11019
                assert settings.bmp_buffer_size == 65536
                assert settings.bmp_max_connections == 100

                # Logging defaults
                assert settings.log_level == "INFO"

    @pytest.mark.unit
    def test_environment_variable_override(self):
        """Test environment variable overrides."""
        env_vars = {
            "DB_HOST": "custom_host",
            "DB_PORT": "5433",
            "DB_NAME": "custom_db",
            "DB_USER": "custom_user",
            "DB_PASSWORD": "custom_password",
            "DB_POOL_SIZE": "50",
            "BMP_LISTEN_HOST": "127.0.0.1",
            "BMP_LISTEN_PORT": "12345",
            "LOG_LEVEL": "DEBUG",
            "DATA_RETENTION_DAYS": "180",
            "BATCH_SIZE": "2000",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            settings = Settings()

            assert settings.db_host == "custom_host"
            assert settings.db_port == 5433
            assert settings.db_name == "custom_db"
            assert settings.db_user == "custom_user"
            assert settings.db_password == "custom_password"
            assert settings.db_pool_size == 50
            assert settings.bmp_listen_host == "127.0.0.1"
            assert settings.bmp_listen_port == 12345
            assert settings.log_level == "DEBUG"
            assert settings.data_retention_days == 180
            assert settings.batch_size == 2000

    @pytest.mark.unit
    def test_log_level_validation_valid(self):
        """Test valid log level validation."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

        for level in valid_levels:
            with patch.dict(os.environ, {"LOG_LEVEL": level, "DB_PASSWORD": "test"}):
                settings = Settings()
                assert settings.log_level == level

    @pytest.mark.unit
    def test_log_level_validation_case_insensitive(self):
        """Test log level validation is case insensitive."""
        with patch.dict(os.environ, {"LOG_LEVEL": "debug", "DB_PASSWORD": "test"}):
            settings = Settings()
            assert settings.log_level == "DEBUG"

    @pytest.mark.unit
    def test_log_level_validation_invalid(self):
        """Test invalid log level validation."""
        with patch.dict(os.environ, {"LOG_LEVEL": "INVALID", "DB_PASSWORD": "test"}):
            with pytest.raises(ValidationError) as exc_info:
                Settings()

            assert "log_level must be one of" in str(exc_info.value)

    @pytest.mark.unit
    def test_database_url_property(self):
        """Test database URL generation."""
        with patch.dict(
            os.environ,
            {
                "DB_HOST": "localhost",
                "DB_PORT": "5432",
                "DB_NAME": "test_db",
                "DB_USER": "test_user",
                "DB_PASSWORD": "test_password",
            },
        ):
            settings = Settings()
            expected_url = "postgresql+asyncpg://test_user:test_password@localhost:5432/test_db"
            assert settings.database_url == expected_url

    @pytest.mark.unit
    def test_sync_database_url_property(self):
        """Test synchronous database URL generation."""
        with patch.dict(
            os.environ,
            {
                "DB_HOST": "localhost",
                "DB_PORT": "5432",
                "DB_NAME": "test_db",
                "DB_USER": "test_user",
                "DB_PASSWORD": "test_password",
            },
        ):
            settings = Settings()
            expected_url = "postgresql://test_user:test_password@localhost:5432/test_db"
            assert settings.sync_database_url == expected_url

    @pytest.mark.unit
    def test_required_password_field(self):
        """Test that password field is required."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()

            # Should fail due to missing required DB_PASSWORD
            assert "db_password" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_env_file_loading(self, temp_directory):
        """Test loading configuration from .env file."""
        env_file_content = """
DB_HOST=file_host
DB_PORT=5433
DB_NAME=file_db
DB_USER=file_user
DB_PASSWORD=file_password
LOG_LEVEL=DEBUG
"""
        env_file_path = os.path.join(temp_directory, ".env")

        with open(env_file_path, "w") as f:
            f.write(env_file_content)

        # Test loading from specific env file path
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings(_env_file=env_file_path)

            assert settings.db_host == "file_host"
            assert settings.db_port == 5433
            assert settings.db_name == "file_db"
            assert settings.db_user == "file_user"
            assert settings.db_password == "file_password"
            assert settings.log_level == "DEBUG"

    @pytest.mark.unit
    def test_env_file_override_by_environment(self, temp_directory):
        """Test that environment variables override .env file."""
        env_file_content = """
DB_HOST=file_host
DB_PASSWORD=file_password
"""
        env_file_path = os.path.join(temp_directory, ".env")

        with open(env_file_path, "w") as f:
            f.write(env_file_content)

        env_vars = {"DB_HOST": "env_host", "DB_PASSWORD": "env_password"}

        with patch("os.getcwd", return_value=temp_directory):
            with patch.dict(os.environ, env_vars):
                settings = Settings()

                # Environment variables should take precedence
                assert settings.db_host == "env_host"
                assert settings.db_password == "env_password"

    @pytest.mark.unit
    def test_numeric_field_validation(self):
        """Test numeric field validation."""
        with patch.dict(os.environ, {"DB_PORT": "invalid_port", "DB_PASSWORD": "test"}):
            with pytest.raises(ValidationError) as exc_info:
                Settings()

            assert "db_port" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_boolean_field_validation(self):
        """Test boolean field validation."""
        # Test various boolean representations
        boolean_tests = [
            ("true", True),
            ("True", True),
            ("1", True),
            ("yes", True),
            ("false", False),
            ("False", False),
            ("0", False),
            ("no", False),
        ]

        for str_value, expected_bool in boolean_tests:
            with patch.dict(os.environ, {"METRICS_ENABLED": str_value, "DB_PASSWORD": "test"}):
                settings = Settings()
                assert settings.metrics_enabled == expected_bool

    @pytest.mark.unit
    def test_config_class_settings(self):
        """Test Config class settings."""
        with patch.dict(os.environ, {"DB_PASSWORD": "test"}):
            settings = Settings()

            # Verify Config class attributes are set correctly
            assert hasattr(settings.Config, "env_file")
            assert settings.Config.env_file == ".env"
            assert settings.Config.env_file_encoding == "utf-8"
            assert settings.Config.case_sensitive is False

    @pytest.mark.unit
    def test_default_field_values(self):
        """Test all default field values."""
        with patch.dict(os.environ, {"DB_PASSWORD": "test_password"}):
            settings = Settings()

            # Database settings
            assert settings.db_host == "localhost"
            assert settings.db_port == 5432
            assert settings.db_name == "bmp_collector"
            assert settings.db_user == "bmp_user"
            assert settings.db_pool_size == 20
            assert settings.db_max_overflow == 40

            # BMP Server settings
            assert settings.bmp_listen_host == "0.0.0.0"
            assert settings.bmp_listen_port == 11019
            assert settings.bmp_buffer_size == 65536
            assert settings.bmp_max_connections == 100

            # Data retention settings
            assert settings.data_retention_days == 90
            assert settings.cleanup_interval_hours == 24

            # Logging settings
            assert settings.log_level == "INFO"
            assert settings.log_format == "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

            # Metrics settings
            assert settings.metrics_enabled is True
            assert settings.metrics_port == 9090

            # Processing settings
            assert settings.batch_size == 1000
            assert settings.batch_timeout_seconds == 5
            assert settings.worker_threads == 4


class TestGetSettings:
    """Test get_settings function."""

    @pytest.mark.unit
    def test_get_settings_returns_settings_instance(self):
        """Test that get_settings returns a Settings instance."""
        with patch.dict(os.environ, {"DB_PASSWORD": "test"}):
            settings = get_settings()
            assert isinstance(settings, Settings)

    @pytest.mark.unit
    def test_get_settings_with_custom_env(self):
        """Test get_settings with custom environment."""
        custom_env = {
            "DB_HOST": "custom.example.com",
            "DB_PASSWORD": "custom_password",
            "LOG_LEVEL": "DEBUG",
        }

        with patch.dict(os.environ, custom_env):
            settings = get_settings()

            assert settings.db_host == "custom.example.com"
            assert settings.db_password == "custom_password"
            assert settings.log_level == "DEBUG"


class TestSettingsEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.unit
    def test_extreme_numeric_values(self):
        """Test handling of extreme numeric values."""
        extreme_env = {
            "DB_PORT": "65535",  # Max port
            "DB_POOL_SIZE": "1000",  # Large pool
            "BMP_BUFFER_SIZE": "1048576",  # 1MB buffer
            "DATA_RETENTION_DAYS": "3650",  # 10 years
            "DB_PASSWORD": "test",
        }

        with patch.dict(os.environ, extreme_env):
            settings = Settings()

            assert settings.db_port == 65535
            assert settings.db_pool_size == 1000
            assert settings.bmp_buffer_size == 1048576
            assert settings.data_retention_days == 3650

    @pytest.mark.unit
    def test_zero_values(self):
        """Test handling of zero values."""
        zero_env = {
            "DB_POOL_SIZE": "0",
            "BMP_MAX_CONNECTIONS": "0",
            "BATCH_SIZE": "0",
            "DB_PASSWORD": "test",
        }

        with patch.dict(os.environ, zero_env):
            settings = Settings()

            assert settings.db_pool_size == 0
            assert settings.bmp_max_connections == 0
            assert settings.batch_size == 0

    @pytest.mark.unit
    def test_special_characters_in_password(self):
        """Test handling of special characters in password."""
        special_passwords = [
            "p@ssw0rd!",
            "password with spaces",
            "пароль",  # Cyrillic
            "密码",  # Chinese
            "p#ss$w%rd^&*()",
        ]

        for password in special_passwords:
            with patch.dict(os.environ, {"DB_PASSWORD": password}):
                settings = Settings()
                assert settings.db_password == password

    @pytest.mark.unit
    def test_missing_env_file(self):
        """Test behavior when .env file doesn't exist."""
        with patch.dict(os.environ, {"DB_PASSWORD": "test"}):
            # Should not raise exception even if .env file doesn't exist
            settings = Settings()
            assert isinstance(settings, Settings)

    @pytest.mark.unit
    def test_malformed_env_file(self, temp_directory):
        """Test handling of malformed .env file."""
        malformed_content = """
DB_HOST=valid_host
INVALID_LINE_WITHOUT_EQUALS
DB_PASSWORD=valid_password
=VALUE_WITHOUT_KEY
"""
        env_file_path = os.path.join(temp_directory, ".env")

        with open(env_file_path, "w") as f:
            f.write(malformed_content)

        with patch.dict(os.environ, {}, clear=True):
            # Should handle malformed lines gracefully
            settings = Settings(_env_file=env_file_path)
            assert settings.db_host == "valid_host"
            assert settings.db_password == "valid_password"

    @pytest.mark.unit
    def test_case_sensitivity_off(self):
        """Test that environment variables are case insensitive."""
        # Note: Actual environment variables are case sensitive in most systems,
        # but pydantic-settings can handle case conversion
        with patch.dict(
            os.environ,
            {"db_password": "test_password", "DB_HOST": "test_host"},  # lowercase  # uppercase
        ):
            settings = Settings()
            # Both should work due to case_sensitive = False
            assert settings.db_password == "test_password"
            assert settings.db_host == "test_host"
