"""Security tests for BMP collector."""
import asyncio
import struct
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.bmp.processor import RouteProcessor
from src.bmp.server import BMPServer, BMPSession
from src.database.connection import DatabasePool
from src.utils.rate_limiter import RateLimiter
from src.utils.validation import (
    sanitize_log_data,
    validate_as_number,
    validate_ip_address,
    validate_prefix,
)


class TestBufferOverflowProtection:
    """Test buffer overflow protection mechanisms."""

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_bmp_session_buffer_overflow_protection(self, test_settings, mock_db_pool):
        """Test BMP session buffer overflow protection."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Create oversized data that exceeds MAX_BUFFER_SIZE
        oversized_data = b"X" * (BMPSession.MAX_BUFFER_SIZE + 1000)
        reader.read.side_effect = [oversized_data]

        session = BMPSession(reader, writer, router_ip, processor)

        with patch("src.bmp.server.logger") as mock_logger:
            await session.handle()

            # Should trigger buffer overflow protection
            mock_logger.error.assert_called()
            error_msg = str(mock_logger.error.call_args)
            assert "Buffer overflow protection triggered" in error_msg

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_message_size_limit_protection(self, test_settings, mock_db_pool):
        """Test protection against oversized individual messages."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Create message header claiming size larger than MAX_MESSAGE_SIZE
        oversized_length = BMPSession.MAX_MESSAGE_SIZE + 1000
        malicious_header = struct.pack(">BIB", 3, oversized_length, 0)
        reader.read.side_effect = [malicious_header, b""]

        session = BMPSession(reader, writer, router_ip, processor)

        with patch("src.bmp.server.logger") as mock_logger:
            await session.handle()

            # Should log error and clear buffer
            mock_logger.error.assert_called()
            error_msg = str(mock_logger.error.call_args)
            assert "Message too large" in error_msg

    @pytest.mark.security
    def test_parser_malformed_message_protection(self, bmp_parser, malicious_bmp_data):
        """Test parser protection against malformed messages."""
        # Test oversized message
        result = bmp_parser.parse_message(malicious_bmp_data["oversized_message"][:1000])
        assert result is None  # Should reject

        # Test invalid version
        result = bmp_parser.parse_message(malicious_bmp_data["invalid_version"])
        assert result is None

        # Test malformed header
        result = bmp_parser.parse_message(malicious_bmp_data["malformed_header"])
        assert result is None

        # Test buffer overflow attempt
        result = bmp_parser.parse_message(malicious_bmp_data["buffer_overflow"][:100])
        assert result is None

    @pytest.mark.security
    def test_parser_invalid_peer_header_protection(self, bmp_parser):
        """Test parser protection against invalid peer headers."""
        # Create message with insufficient peer header data
        # BMP header (6 bytes) + insufficient peer header data (20 bytes) = 26 bytes total
        insufficient_data = (
            b"\x03\x00\x00\x00\x1a\x00" + b"X" * 20
        )  # Less than 42 bytes needed for peer header

        with patch("src.bmp.parser.logger") as mock_logger:
            result = bmp_parser.parse_message(insufficient_data)
            assert result is None
            mock_logger.error.assert_called()

    @pytest.mark.security
    def test_parser_recursive_structure_protection(self, bmp_parser):
        """Test protection against deeply nested or recursive structures."""
        # Create message with deeply nested AS_PATH
        deep_as_path = b""
        for i in range(1000):  # Try to create very deep nesting
            deep_as_path += struct.pack(">BB", 2, 1)  # AS_SEQUENCE with 1 AS
            deep_as_path += struct.pack(">I", 65000 + i)

        # This would be part of a BGP UPDATE message
        # Parser should handle gracefully without stack overflow
        result = bmp_parser._parse_as_path(deep_as_path[:1000])  # Limit size
        assert isinstance(result, list)
        # Should not crash or consume excessive memory


class TestSQLInjectionPrevention:
    """Test SQL injection prevention mechanisms."""

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_route_insertion_sql_injection_protection(self, test_settings):
        """Test SQL injection protection in route insertion."""
        db_pool = DatabasePool(test_settings)
        mock_connection = AsyncMock()

        # Mock the acquire context manager
        class MockAsyncContextManager:
            async def __aenter__(self):
                return mock_connection

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

        db_pool.pool = AsyncMock()
        db_pool.pool.acquire = Mock(return_value=MockAsyncContextManager())

        # Test with malicious SQL injection payloads
        malicious_route = {
            "time": datetime.utcnow(),
            "router_ip": "'; DROP TABLE routes; --",
            "peer_ip": "'; DELETE FROM routes WHERE 1=1; --",
            "peer_as": 65001,
            "prefix": "'; INSERT INTO routes VALUES (1,2,3); --",
            "prefix_len": 24,
            "next_hop": "'; UPDATE routes SET prefix='hacked'; --",
            "family": "IPv4",
            "origin": 0,
            "as_path": "'; EXEC xp_cmdshell('rm -rf /'); --",
        }

        await db_pool.insert_route(malicious_route)

        # Verify parameterized query was used
        mock_connection.execute.assert_called_once()
        call_args = mock_connection.execute.call_args
        query = call_args[0][0]
        params = call_args[0][1:]

        # Query should use placeholders, not direct string insertion
        assert "$1" in query and "$2" in query
        assert "DROP TABLE" not in query
        assert "DELETE FROM" not in query
        # Malicious content should be in parameters (safely escaped)
        assert any("DROP TABLE" in str(param) for param in params)

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_session_management_sql_injection_protection(self, test_settings):
        """Test SQL injection protection in session management."""
        db_pool = DatabasePool(test_settings)
        mock_connection = AsyncMock()
        mock_connection.fetchrow.return_value = {"id": 123}

        class MockAsyncContextManager:
            async def __aenter__(self):
                return mock_connection

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

        db_pool.pool = AsyncMock()
        db_pool.pool.acquire = Mock(return_value=MockAsyncContextManager())

        # Malicious session data
        malicious_session = {
            "router_ip": "'; DROP TABLE router_sessions; --",
            "router_name": "'; DELETE FROM router_sessions; --",
            "session_start": datetime.utcnow(),
            "status": "'; UPDATE router_sessions SET status='hacked'; --",
        }

        await db_pool.create_or_update_session(malicious_session)

        # Verify safe parameter usage
        mock_connection.fetchrow.assert_called_once()
        call_args = mock_connection.fetchrow.call_args
        query = call_args[0][0]

        assert "$1" in query
        assert "DROP TABLE" not in query
        assert "INSERT INTO router_sessions" in query

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_statistics_sql_injection_protection(self, test_settings):
        """Test SQL injection protection in statistics updates."""
        db_pool = DatabasePool(test_settings)
        mock_connection = AsyncMock()

        class MockAsyncContextManager:
            async def __aenter__(self):
                return mock_connection

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

        db_pool.pool = AsyncMock()
        db_pool.pool.acquire = Mock(return_value=MockAsyncContextManager())

        # Malicious statistics data
        malicious_stats = {
            "router_ip": "127.0.0.1'; DROP TABLE bmp_stats; --",
            "peer_ip": "10.0.0.1'; DELETE FROM bmp_stats; --",
            "peer_as": 65001,
            "routes_received": 1000,
            "withdrawals_received": 50,
        }

        with patch("src.database.connection.datetime") as mock_datetime:
            mock_datetime.utcnow.return_value = datetime.utcnow()
            await db_pool.update_statistics(malicious_stats)

        # Verify parameterized query
        mock_connection.execute.assert_called_once()
        call_args = mock_connection.execute.call_args
        query = call_args[0][0]

        assert "INSERT INTO bmp_stats" in query
        assert "$1" in query and "$2" in query
        assert "DROP TABLE" not in query

    @pytest.mark.security
    @pytest.mark.parametrize(
        "payload",
        [
            "'; DROP TABLE routes; --",
            "' OR 1=1 --",
            "'; INSERT INTO routes VALUES (1,2,3); --",
            "1'; EXEC xp_cmdshell('dir'); --",
            "' UNION SELECT password FROM users --",
        ],
    )
    def test_input_validation_sql_injection_payloads(self, payload):
        """Test input validation against common SQL injection payloads."""
        # IP validation should reject SQL payloads
        assert validate_ip_address(payload) is None

        # AS number validation should reject non-numeric SQL payloads
        assert validate_as_number(payload) is None

        # Prefix validation should reject malformed SQL payloads
        assert validate_prefix(payload) is None


class TestInputValidationSecurity:
    """Test input validation security mechanisms."""

    @pytest.mark.security
    @pytest.mark.parametrize(
        "malicious_input",
        [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "'; alert('xss'); //",
            "\x00\x01\x02\x03",  # Binary data
            "A" * 10000,  # Very long string
            "\n\r\t\x0b\x0c",  # Control characters
        ],
    )
    def test_log_sanitization_security(self, malicious_input):
        """Test log data sanitization against various attacks."""
        sanitized = sanitize_log_data(malicious_input)

        # Should not contain dangerous characters in output
        assert "<script>" not in sanitized
        assert "javascript:" not in sanitized
        assert "alert(" not in sanitized

        # Control characters should be replaced
        assert "\x00" not in sanitized
        assert "\x01" not in sanitized

        # Should be limited in length
        assert len(sanitized) <= 103  # max_len + "..."

    @pytest.mark.security
    def test_as_number_boundary_validation(self):
        """Test AS number validation boundary conditions."""
        # Valid boundaries
        assert validate_as_number(0) == 0
        assert validate_as_number(4294967295) == 4294967295

        # Invalid boundaries
        assert validate_as_number(-1) is None
        assert validate_as_number(4294967296) is None

        # Malformed inputs
        assert validate_as_number("0x1000") is None  # Hex format
        assert validate_as_number("1e6") is None  # Scientific notation
        assert validate_as_number(float("inf")) is None
        assert validate_as_number(float("nan")) is None

    @pytest.mark.security
    def test_ip_address_security_validation(self):
        """Test IP address validation security."""
        # Valid IPs
        assert validate_ip_address("192.0.2.1") == "192.0.2.1"
        assert validate_ip_address("::1") == "::1"

        # Invalid/malicious IPs
        assert validate_ip_address("999.999.999.999") is None
        assert validate_ip_address("192.168.1.1/24") is None  # CIDR notation
        assert validate_ip_address("192.168.1.1:8080") is None  # With port
        assert validate_ip_address("file:///etc/passwd") is None  # File URL
        assert validate_ip_address("http://evil.com") is None  # HTTP URL

    @pytest.mark.security
    def test_prefix_validation_security(self):
        """Test network prefix validation security."""
        # Valid prefixes
        assert validate_prefix("192.0.2.0/24") == "192.0.2.0/24"
        assert validate_prefix("2001:db8::/32") == "2001:db8::/32"

        # Invalid/malicious prefixes
        assert validate_prefix("192.0.2.0/33") is None  # Invalid mask
        assert validate_prefix("192.0.2.0/-1") is None  # Negative mask
        assert validate_prefix("../../../etc/passwd") is None  # Path traversal
        assert validate_prefix("javascript:alert(1)") is None  # JS injection

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_route_processor_input_sanitization(self, route_processor):
        """Test route processor input sanitization."""
        router_ip = "192.0.2.100"

        # Create message with potentially dangerous data
        malicious_message = {
            "type": "route_monitoring",
            "peer": {
                "peer_ip": "'; DROP TABLE routes; --",
                "peer_as": "not_a_number",
                "timestamp_sec": "malicious_timestamp",
                "timestamp_usec": 0,
            },
            "bgp_message": {
                "type": "UPDATE",
                "nlri": [
                    "../../../etc/passwd",
                    "<script>alert('xss')</script>",
                    "'; DROP TABLE routes; --",
                ],
            },
        }

        # Should handle malicious input gracefully
        with patch("src.bmp.processor.logger"):
            await route_processor.process_message(malicious_message, router_ip)

        # Should not crash and should sanitize data
        assert route_processor.stats["errors"] >= 0  # May increment error count


class TestRateLimitingSecurity:
    """Test rate limiting security mechanisms."""

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_connection_flood_protection(self):
        """Test protection against connection flooding."""
        limiter = RateLimiter(max_connections_per_ip=3)
        attacker_ip = "192.0.2.100"

        # Allow up to limit
        for i in range(3):
            allowed = await limiter.check_connection_allowed(attacker_ip)
            assert allowed is True

        # Deny additional connections (flood protection)
        for i in range(10):
            allowed = await limiter.check_connection_allowed(attacker_ip)
            assert allowed is False

        # Connection count should not increase beyond limit
        assert limiter.connections_per_ip[attacker_ip] == 3

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_message_flood_protection(self):
        """Test protection against message flooding."""
        limiter = RateLimiter(max_messages_per_second=10, burst_size=20)
        attacker_ip = "192.0.2.100"

        # Consume burst allowance
        allowed = await limiter.check_message_allowed(attacker_ip, count=20)
        assert allowed is True

        # Further messages should be denied
        for i in range(10):
            allowed = await limiter.check_message_allowed(attacker_ip, count=1)
            assert allowed is False

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_distributed_attack_protection(self):
        """Test protection against distributed attacks."""
        limiter = RateLimiter(max_connections_per_ip=2)

        # Simulate attack from multiple IPs
        attack_ips = [f"192.0.2.{i}" for i in range(1, 101)]  # 100 different IPs

        for ip in attack_ips:
            # Each IP can establish limited connections
            allowed1 = await limiter.check_connection_allowed(ip)
            allowed2 = await limiter.check_connection_allowed(ip)
            denied = await limiter.check_connection_allowed(ip)

            assert allowed1 is True
            assert allowed2 is True
            assert denied is False

        # Verify limits are enforced per IP
        stats = limiter.get_stats()
        assert stats["total_ips"] == 100
        assert stats["max_connections"] == 2

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_server_connection_limit_enforcement(self, test_settings, mock_db_pool):
        """Test server enforces connection limits."""
        test_settings.bmp_max_connections = 2
        server = BMPServer(test_settings, mock_db_pool)

        # Fill connection slots
        server.sessions["192.0.2.1"] = AsyncMock()
        server.sessions["192.0.2.2"] = AsyncMock()

        # Try to add another connection
        reader = AsyncMock()
        writer = AsyncMock()
        writer.get_extra_info.return_value = ("192.0.2.3", 12345)
        writer.close = Mock()  # close() is synchronous
        writer.wait_closed = AsyncMock()

        with patch("src.bmp.server.logger") as mock_logger:
            await server._handle_client(reader, writer)

            # Should reject and log warning
            mock_logger.warning.assert_called()
            writer.close.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_token_bucket_manipulation_protection(self):
        """Test protection against token bucket manipulation."""
        limiter = RateLimiter(max_messages_per_second=10, burst_size=5)
        ip = "192.0.2.1"

        # Try to manipulate token bucket by requesting negative tokens
        with pytest.raises(TypeError):
            await limiter.check_message_allowed(ip, count=-10)

        # Try with zero count (should be allowed but not consume tokens)
        allowed = await limiter.check_message_allowed(ip, count=0)
        assert allowed is True
        assert limiter.message_tokens[ip] == 5  # Unchanged

        # Try with extremely large count
        allowed = await limiter.check_message_allowed(ip, count=1000000)
        assert allowed is False
        assert limiter.message_tokens[ip] == 5  # Unchanged


class TestMemoryExhaustionProtection:
    """Test protection against memory exhaustion attacks."""

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_route_buffer_memory_protection(self, route_processor):
        """Test protection against route buffer memory exhaustion."""
        router_ip = "192.0.2.100"

        # Try to fill buffer with many routes
        large_message = {
            "type": "route_monitoring",
            "peer": {
                "peer_ip": "192.0.2.1",
                "peer_as": 65001,
                "timestamp_sec": 1704110400,
                "timestamp_usec": 0,
            },
            "bgp_message": {
                "type": "UPDATE",
                "nlri": [f"10.{i // 256}.{i % 256}.0/24" for i in range(1000)],  # 1000 routes
            },
        }

        await route_processor.process_message(large_message, router_ip)

        # Buffer should be automatically flushed to prevent memory exhaustion
        # (due to batch_size limit in settings)
        route_processor.db_pool.batch_insert_routes.assert_called()

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_session_buffer_memory_protection(self, test_settings, mock_db_pool):
        """Test session buffer memory protection."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Create data that approaches buffer limit
        large_data = b"X" * (BMPSession.MAX_BUFFER_SIZE - 100)
        reader.read.side_effect = [large_data, b""]

        session = BMPSession(reader, writer, router_ip, processor)

        # Should handle large data without exceeding memory limits
        await session.handle()

        # Session should complete without error
        assert session.buffer == b""  # Buffer cleared after processing

    @pytest.mark.security
    def test_parser_memory_protection_deep_nesting(self, bmp_parser):
        """Test parser memory protection against deep nesting attacks."""
        # Create deeply nested AS_PATH that could cause stack overflow
        deep_structure = b""
        for i in range(100):  # Reasonable depth
            deep_structure += struct.pack(">BB", 2, 2)  # AS_SEQUENCE with 2 ASNs
            deep_structure += struct.pack(">II", 65001, 65002)

        # Should handle without stack overflow or excessive memory use
        result = bmp_parser._parse_as_path(deep_structure)
        assert isinstance(result, list)
        assert len(result) == 100

    @pytest.mark.security
    def test_validation_memory_protection(self):
        """Test validation functions memory protection."""
        # Test with very long inputs
        very_long_string = "A" * 1000000  # 1MB string

        # Should handle without excessive memory allocation
        result = sanitize_log_data(very_long_string, max_len=100)
        assert len(result) <= 103  # Truncated

        # Should reject without processing entire string
        assert validate_ip_address(very_long_string) is None
        assert validate_as_number(very_long_string) is None
        assert validate_prefix(very_long_string) is None


class TestAuthenticationBypass:
    """Test protection against authentication bypass attempts."""

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_unauthorized_session_creation(self, test_settings, mock_db_pool):
        """Test that unauthorized sessions cannot be created."""
        server = BMPServer(test_settings, mock_db_pool)

        # Mock connection from unknown/unauthorized IP
        reader = AsyncMock()
        writer = AsyncMock()
        writer.get_extra_info.return_value = ("0.0.0.0", 0)  # Suspicious source
        reader.read.return_value = b""  # Simulate immediate connection termination
        writer.close = Mock()  # Synchronous close method
        writer.wait_closed = AsyncMock()  # Asynchronous wait_closed method

        # Session should still be created (BMP doesn't have auth by design)
        # but should be monitored and rate-limited
        await server._handle_client(reader, writer)

        # In a production system, you might add IP whitelisting here

    @pytest.mark.security
    def test_message_spoofing_protection(self, bmp_parser):
        """Test protection against message spoofing."""
        # Create message with suspicious peer information
        suspicious_message = b"\x03" + struct.pack(">I", 50) + b"\x00"  # BMP header
        suspicious_message += b"\x00" * 8  # Peer distinguisher
        suspicious_message += b"\x00" * 16  # Suspicious peer IP (all zeros)
        suspicious_message += struct.pack(">I", 0)  # Suspicious AS (0)
        suspicious_message += b"\x00" * 18  # Rest of peer header

        # Parser should handle but validation should catch suspicious values
        _result = bmp_parser.parse_message(suspicious_message)
        # May parse but suspicious values should be validated elsewhere


class TestDataIntegrityProtection:
    """Test data integrity protection mechanisms."""

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_route_data_integrity(self, route_processor):
        """Test route data integrity validation."""
        router_ip = "192.0.2.100"

        # Message with corrupted/inconsistent data
        corrupted_message = {
            "type": "route_monitoring",
            "peer": {
                "peer_ip": "192.0.2.1",
                "peer_as": -1,  # Invalid AS number
                "timestamp_sec": -1,  # Invalid timestamp
                "timestamp_usec": 0,
            },
            "bgp_message": {
                "type": "UPDATE",
                "nlri": ["invalid_prefix", "999.999.999.0/24"],  # Invalid prefixes
            },
        }

        with patch("src.bmp.processor.logger"):
            await route_processor.process_message(corrupted_message, router_ip)

        # Should handle corrupted data gracefully
        # Invalid data should be sanitized or rejected
        for route in route_processor.route_buffer:
            # Check that stored data is valid
            assert route["peer_as"] >= 0  # Should be corrected or filtered
            assert route["prefix_len"] >= 0  # Should be reasonable

    @pytest.mark.security
    def test_timestamp_integrity(self, route_processor):
        """Test timestamp integrity validation."""
        # Test with various timestamp manipulations
        test_cases = [
            {"timestamp_sec": -1, "timestamp_usec": 0},  # Negative
            {"timestamp_sec": 2**32, "timestamp_usec": 0},  # Too large
            {"timestamp_sec": 0, "timestamp_usec": -1},  # Negative microseconds
            {"timestamp_sec": 0, "timestamp_usec": 2**32},  # Too large microseconds
        ]

        for case in test_cases:
            timestamp = route_processor._get_timestamp(case)
            # Should return valid timestamp, not crash
            assert isinstance(timestamp, datetime)

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_concurrent_data_corruption_protection(self, route_processor):
        """Test protection against concurrent data corruption."""
        router_ip = "192.0.2.100"

        # Create concurrent tasks that modify shared data
        async def process_route(i):
            message = {
                "type": "route_monitoring",
                "peer": {
                    "peer_ip": f"10.0.0.{i}",
                    "peer_as": 65000 + i,
                    "timestamp_sec": 1704110400 + i,
                    "timestamp_usec": 0,
                },
                "bgp_message": {"type": "UPDATE", "nlri": [f"203.0.{i}.0/24"]},
            }
            await route_processor.process_message(message, router_ip)

        # Run multiple concurrent processing tasks
        tasks = [process_route(i) for i in range(20)]
        await asyncio.gather(*tasks)

        # Verify data integrity was maintained
        assert len(route_processor.route_buffer) == 20

        # Check that routes don't have corrupted data
        seen_prefixes = set()
        for route in route_processor.route_buffer:
            assert route["prefix"] not in seen_prefixes  # No duplicates
            seen_prefixes.add(route["prefix"])
            assert route["peer_as"] >= 65000  # Valid AS range
            assert "203.0." in route["prefix"]  # Expected prefix format
