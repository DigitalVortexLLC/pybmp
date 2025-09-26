"""Unit tests for validation utilities."""
import pytest
import ipaddress

from src.utils.validation import (
    validate_as_number,
    validate_ip_address,
    validate_prefix,
    validate_message_length,
    validate_port,
    sanitize_log_data,
)


class TestValidateAsNumber:
    """Test AS number validation."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "as_num,expected",
        [
            (0, 0),
            (65000, 65000),
            (4294967295, 4294967295),  # Max 32-bit AS number
            ("65001", 65001),  # String representation
            ("0", 0),
            (1.0, 1),  # Float that can be converted
        ],
    )
    def test_valid_as_numbers(self, as_num, expected):
        """Test valid AS numbers."""
        result = validate_as_number(as_num)
        assert result == expected

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "as_num",
        [
            -1,  # Negative
            4294967296,  # Too large
            "invalid",  # Non-numeric string
            None,  # None value
            [],  # Invalid type
            {},  # Invalid type
            float("inf"),  # Infinity
            float("nan"),  # NaN
        ],
    )
    def test_invalid_as_numbers(self, as_num):
        """Test invalid AS numbers."""
        result = validate_as_number(as_num)
        assert result is None

    @pytest.mark.unit
    def test_as_number_edge_cases(self):
        """Test AS number edge cases."""
        # Test maximum valid value
        assert validate_as_number(4294967295) == 4294967295

        # Test minimum valid value
        assert validate_as_number(0) == 0

        # Test one beyond maximum
        assert validate_as_number(4294967296) is None

        # Test string with whitespace
        assert validate_as_number("  65001  ") == 65001


class TestValidateIpAddress:
    """Test IP address validation."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "ip,expected",
        [
            ("192.0.2.1", "192.0.2.1"),
            ("10.0.0.1", "10.0.0.1"),
            ("127.0.0.1", "127.0.0.1"),
            ("255.255.255.255", "255.255.255.255"),
            ("0.0.0.0", "0.0.0.0"),
            ("2001:db8::1", "2001:db8::1"),
            ("::1", "::1"),
            ("2001:db8:85a3:8d3:1319:8a2e:370:7348", "2001:db8:85a3:8d3:1319:8a2e:370:7348"),
            ("::", "::"),
        ],
    )
    def test_valid_ip_addresses(self, ip, expected):
        """Test valid IP addresses."""
        result = validate_ip_address(ip)
        assert result == expected

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "ip",
        [
            "256.0.0.1",  # Invalid IPv4
            "192.168.1",  # Incomplete IPv4
            "192.168.1.1.1",  # Too many octets
            "invalid",  # Non-IP string
            "2001:db8::gg",  # Invalid IPv6
            "",  # Empty string
            None,  # None value
            123,  # Integer
            [],  # Invalid type
        ],
    )
    def test_invalid_ip_addresses(self, ip):
        """Test invalid IP addresses."""
        result = validate_ip_address(ip)
        assert result is None

    @pytest.mark.unit
    def test_ip_address_edge_cases(self):
        """Test IP address edge cases."""
        # Test IPv4 mapped IPv6
        result = validate_ip_address("::ffff:192.0.2.1")
        assert result == "::ffff:192.0.2.1"

        # Test compressed IPv6
        result = validate_ip_address("2001:db8::8a2e:370:7334")
        assert result == "2001:db8::8a2e:370:7334"


class TestValidatePrefix:
    """Test network prefix validation."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "prefix,expected",
        [
            ("192.0.2.0/24", "192.0.2.0/24"),
            ("10.0.0.0/8", "10.0.0.0/8"),
            ("172.16.0.0/12", "172.16.0.0/12"),
            ("0.0.0.0/0", "0.0.0.0/0"),
            ("192.0.2.1/32", "192.0.2.1/32"),
            ("2001:db8::/32", "2001:db8::/32"),
            ("::/0", "::/0"),
            ("2001:db8::1/128", "2001:db8::1/128"),
        ],
    )
    def test_valid_prefixes(self, prefix, expected):
        """Test valid network prefixes."""
        result = validate_prefix(prefix)
        assert result == expected

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "prefix",
        [
            "192.0.2.0/33",  # Invalid IPv4 prefix length
            "192.0.2.0/-1",  # Negative prefix length
            "256.0.0.0/24",  # Invalid IPv4 address
            "192.0.2.0",  # Missing prefix length
            "192.0.2.0/",  # Empty prefix length
            "invalid/24",  # Invalid address
            "",  # Empty string
            None,  # None value
            "2001:db8::/129",  # Invalid IPv6 prefix length
        ],
    )
    def test_invalid_prefixes(self, prefix):
        """Test invalid network prefixes."""
        result = validate_prefix(prefix)
        assert result is None

    @pytest.mark.unit
    def test_prefix_strict_mode(self):
        """Test prefix validation with strict=False (default)."""
        # Should normalize host bits
        result = validate_prefix("192.0.2.1/24")
        assert result == "192.0.2.0/24"  # Host bits zeroed

        # Test IPv6
        result = validate_prefix("2001:db8::1/64")
        assert result == "2001:db8::/64"

    @pytest.mark.unit
    def test_prefix_edge_cases(self):
        """Test prefix edge cases."""
        # Test /0 prefixes
        assert validate_prefix("0.0.0.0/0") == "0.0.0.0/0"
        assert validate_prefix("::/0") == "::/0"

        # Test maximum prefix lengths
        assert validate_prefix("192.0.2.1/32") == "192.0.2.1/32"
        assert validate_prefix("2001:db8::1/128") == "2001:db8::1/128"


class TestValidateMessageLength:
    """Test BMP message length validation."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "length,expected",
        [
            (6, True),  # Minimum valid
            (100, True),  # Normal size
            (1048576, True),  # Default maximum
            (500000, True),  # Large but valid
        ],
    )
    def test_valid_message_lengths(self, length, expected):
        """Test valid message lengths."""
        result = validate_message_length(length)
        assert result == expected

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "length",
        [
            5,  # Too small
            0,  # Zero
            -1,  # Negative
            1048577,  # Too large (default max)
        ],
    )
    def test_invalid_message_lengths(self, length):
        """Test invalid message lengths."""
        result = validate_message_length(length)
        assert result is False

    @pytest.mark.unit
    def test_custom_max_size(self):
        """Test custom maximum size."""
        # Test with custom max size
        assert validate_message_length(2000, max_size=5000) is True
        assert validate_message_length(6000, max_size=5000) is False

    @pytest.mark.unit
    def test_message_length_boundary_conditions(self):
        """Test boundary conditions."""
        # Test exact boundaries
        assert validate_message_length(6) is True  # Minimum
        assert validate_message_length(5) is False  # Below minimum
        assert validate_message_length(1048576) is True  # Maximum
        assert validate_message_length(1048577) is False  # Above maximum


class TestValidatePort:
    """Test port number validation."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "port,expected",
        [
            (1, 1),  # Minimum valid
            (80, 80),  # Common port
            (65535, 65535),  # Maximum valid
            ("22", 22),  # String representation
            ("443", 443),
            (1.0, 1),  # Float that can be converted
        ],
    )
    def test_valid_ports(self, port, expected):
        """Test valid port numbers."""
        result = validate_port(port)
        assert result == expected

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "port",
        [
            0,  # Invalid (too small)
            -1,  # Negative
            65536,  # Too large
            "invalid",  # Non-numeric string
            None,  # None value
            [],  # Invalid type
            float("inf"),  # Infinity
        ],
    )
    def test_invalid_ports(self, port):
        """Test invalid port numbers."""
        result = validate_port(port)
        assert result is None

    @pytest.mark.unit
    def test_port_edge_cases(self):
        """Test port edge cases."""
        # Test boundaries
        assert validate_port(1) == 1  # Minimum
        assert validate_port(65535) == 65535  # Maximum
        assert validate_port(0) is None  # Below minimum
        assert validate_port(65536) is None  # Above maximum


class TestSanitizeLogData:
    """Test log data sanitization."""

    @pytest.mark.unit
    def test_sanitize_bytes(self):
        """Test sanitizing bytes data."""
        test_bytes = b"\x01\x02\x03\xff"
        result = sanitize_log_data(test_bytes)
        assert result == "010203ff"

    @pytest.mark.unit
    def test_sanitize_long_bytes(self):
        """Test sanitizing long bytes data."""
        long_bytes = b"x" * 150
        result = sanitize_log_data(long_bytes, max_len=100)
        assert len(result) == 103  # 100 + "..."
        assert result.endswith("...")

    @pytest.mark.unit
    def test_sanitize_string(self):
        """Test sanitizing string data."""
        test_string = "normal string"
        result = sanitize_log_data(test_string)
        assert result == "normal string"

    @pytest.mark.unit
    def test_sanitize_string_with_control_chars(self):
        """Test sanitizing string with control characters."""
        test_string = "string\x00with\x01control\x02chars"
        result = sanitize_log_data(test_string)
        assert result == "string?with?control?chars"

    @pytest.mark.unit
    def test_sanitize_long_string(self):
        """Test sanitizing long string."""
        long_string = "x" * 150
        result = sanitize_log_data(long_string, max_len=100)
        assert len(result) == 103  # 100 + "..."
        assert result.endswith("...")

    @pytest.mark.unit
    def test_sanitize_mixed_printable_non_printable(self):
        """Test sanitizing mixed printable and non-printable characters."""
        test_string = "Hello\x00World\x7fTest"
        result = sanitize_log_data(test_string)
        assert result == "Hello?World?Test"

    @pytest.mark.unit
    def test_sanitize_unicode(self):
        """Test sanitizing unicode strings."""
        unicode_string = "Hello 世界 🌍"
        result = sanitize_log_data(unicode_string)
        assert result == "Hello 世界 🌍"

    @pytest.mark.unit
    def test_sanitize_numbers(self):
        """Test sanitizing numeric data."""
        assert sanitize_log_data(123) == "123"
        assert sanitize_log_data(45.67) == "45.67"
        assert sanitize_log_data(-89) == "-89"

    @pytest.mark.unit
    def test_sanitize_none(self):
        """Test sanitizing None value."""
        result = sanitize_log_data(None)
        assert result == "None"

    @pytest.mark.unit
    def test_sanitize_empty_data(self):
        """Test sanitizing empty data."""
        assert sanitize_log_data("") == ""
        assert sanitize_log_data(b"") == ""

    @pytest.mark.unit
    def test_custom_max_length(self):
        """Test custom max length parameter."""
        long_string = "a" * 50
        result = sanitize_log_data(long_string, max_len=20)
        assert len(result) == 23  # 20 + "..."
        assert result == "a" * 20 + "..."

    @pytest.mark.unit
    def test_sanitize_special_characters(self):
        """Test sanitizing strings with special characters."""
        special_chars = "!@#$%^&*()_+-=[]{}|;:'\",.<>?/~`"
        result = sanitize_log_data(special_chars)
        assert result == special_chars  # All should be printable

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "test_input,expected",
        [
            (b"\x00\x01\x02", "000102"),
            ("test\nstring", "test?string"),  # Newline is control char
            ("test\tstring", "test\tstring"),  # Tab is printable
            (12345, "12345"),
            ([], "[]"),
            ({}, "{}"),
        ],
    )
    def test_sanitize_various_inputs(self, test_input, expected):
        """Test sanitizing various input types."""
        result = sanitize_log_data(test_input)
        assert result == expected


class TestValidationEdgeCases:
    """Test edge cases and boundary conditions for all validators."""

    @pytest.mark.unit
    def test_validate_with_extreme_values(self):
        """Test validators with extreme values."""
        # Test very large AS number
        assert validate_as_number(2**32 - 1) == 2**32 - 1
        assert validate_as_number(2**32) is None

        # Test very large port
        assert validate_port(65535) == 65535
        assert validate_port(65536) is None

        # Test very large message length
        assert validate_message_length(1048576) is True
        assert validate_message_length(1048577) is False

    @pytest.mark.unit
    def test_validate_with_type_coercion(self):
        """Test validators with type coercion."""
        # Test string to int conversion
        assert validate_as_number("65001") == 65001
        assert validate_port("8080") == 8080

        # Test float to int conversion
        assert validate_as_number(65001.0) == 65001
        assert validate_port(8080.0) == 8080

    @pytest.mark.unit
    def test_validate_with_whitespace(self):
        """Test validators handling whitespace."""
        # AS number should handle string whitespace
        assert validate_as_number("  65001  ") == 65001

        # IP addresses should handle internal format
        assert validate_ip_address("192.0.2.1") == "192.0.2.1"

    @pytest.mark.unit
    def test_memory_efficiency_large_data(self):
        """Test memory efficiency with large data."""
        # Test sanitization with very large input
        large_bytes = b"x" * 10000
        result = sanitize_log_data(large_bytes, max_len=50)

        # Should truncate efficiently
        assert len(result) == 53  # 50 + "..."
        assert result.endswith("...")

    @pytest.mark.unit
    def test_concurrent_validation(self):
        """Test that validators work correctly under concurrent access."""
        # These functions should be stateless and thread-safe
        import threading
        import time

        results = []
        errors = []

        def worker():
            try:
                for i in range(100):
                    # Test various validators
                    assert validate_as_number(65000 + i) == 65000 + i
                    assert validate_port(8000 + i) == 8000 + i
                    assert validate_ip_address("192.0.2.1") == "192.0.2.1"
                    results.append(i)
            except Exception as e:
                errors.append(e)

        threads = []
        for _ in range(10):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Should have no errors and all results
        assert len(errors) == 0
        assert len(results) == 1000  # 10 threads * 100 iterations
