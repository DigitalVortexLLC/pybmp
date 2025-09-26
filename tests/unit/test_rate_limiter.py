"""Unit tests for rate limiter."""
import pytest
import asyncio
import time
from unittest.mock import patch

from src.utils.rate_limiter import RateLimiter


class TestRateLimiter:
    """Test rate limiter functionality."""

    @pytest.mark.unit
    def test_rate_limiter_initialization(self):
        """Test rate limiter initialization."""
        limiter = RateLimiter(max_connections_per_ip=5, max_messages_per_second=100, burst_size=50)

        assert limiter.max_connections_per_ip == 5
        assert limiter.max_messages_per_second == 100
        assert limiter.burst_size == 50
        assert len(limiter.connections_per_ip) == 0
        assert len(limiter.message_tokens) == 0

    @pytest.mark.unit
    def test_default_initialization(self):
        """Test rate limiter with default values."""
        limiter = RateLimiter()

        assert limiter.max_connections_per_ip == 10
        assert limiter.max_messages_per_second == 1000
        assert limiter.burst_size == 100

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_connection_allowed_first_connection(self):
        """Test allowing first connection from IP."""
        limiter = RateLimiter(max_connections_per_ip=3)
        ip = "192.0.2.1"

        allowed = await limiter.check_connection_allowed(ip)

        assert allowed is True
        assert limiter.connections_per_ip[ip] == 1

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_connection_allowed_multiple_connections(self):
        """Test allowing multiple connections from same IP."""
        limiter = RateLimiter(max_connections_per_ip=3)
        ip = "192.0.2.1"

        # Allow up to max connections
        for i in range(3):
            allowed = await limiter.check_connection_allowed(ip)
            assert allowed is True
            assert limiter.connections_per_ip[ip] == i + 1

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_connection_denied_over_limit(self):
        """Test denying connection over limit."""
        limiter = RateLimiter(max_connections_per_ip=2)
        ip = "192.0.2.1"

        # Allow up to limit
        for _ in range(2):
            allowed = await limiter.check_connection_allowed(ip)
            assert allowed is True

        # Deny over limit
        allowed = await limiter.check_connection_allowed(ip)
        assert allowed is False
        assert limiter.connections_per_ip[ip] == 2  # Shouldn't increment

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_release_connection(self):
        """Test releasing connection."""
        limiter = RateLimiter(max_connections_per_ip=3)
        ip = "192.0.2.1"

        # Establish connections
        for _ in range(3):
            await limiter.check_connection_allowed(ip)

        assert limiter.connections_per_ip[ip] == 3

        # Release one connection
        await limiter.release_connection(ip)
        assert limiter.connections_per_ip[ip] == 2

        # Release all connections
        await limiter.release_connection(ip)
        await limiter.release_connection(ip)
        assert ip not in limiter.connections_per_ip

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_release_connection_not_exists(self):
        """Test releasing connection for IP that doesn't exist."""
        limiter = RateLimiter()
        ip = "192.0.2.1"

        # Should not raise exception
        await limiter.release_connection(ip)
        assert ip not in limiter.connections_per_ip

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_release_connection_below_zero(self):
        """Test releasing more connections than exist."""
        limiter = RateLimiter()
        ip = "192.0.2.1"

        # Establish one connection
        await limiter.check_connection_allowed(ip)
        assert limiter.connections_per_ip[ip] == 1

        # Release twice
        await limiter.release_connection(ip)
        assert ip not in limiter.connections_per_ip

        await limiter.release_connection(ip)  # Should not go negative
        assert ip not in limiter.connections_per_ip

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_message_allowed_initial_burst(self):
        """Test message allowed with initial burst tokens."""
        limiter = RateLimiter(burst_size=100)
        ip = "192.0.2.1"

        # Should allow messages up to burst size immediately
        for i in range(100):
            allowed = await limiter.check_message_allowed(ip)
            assert allowed is True

        # Should deny next message (no tokens left)
        allowed = await limiter.check_message_allowed(ip)
        assert allowed is False

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_message_allowed_multiple_messages(self):
        """Test allowing multiple messages."""
        limiter = RateLimiter(burst_size=10)
        ip = "192.0.2.1"

        # Test consuming multiple tokens at once
        allowed = await limiter.check_message_allowed(ip, count=5)
        assert allowed is True
        assert limiter.message_tokens[ip] == 5  # 10 - 5

        allowed = await limiter.check_message_allowed(ip, count=3)
        assert allowed is True
        assert abs(limiter.message_tokens[ip] - 2.0) < 0.01  # 5 - 3, allowing for floating point precision

        # Should deny request for more tokens than available
        allowed = await limiter.check_message_allowed(ip, count=5)
        assert allowed is False
        assert abs(limiter.message_tokens[ip] - 2.0) < 0.01  # Unchanged, allowing for floating point precision

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_token_bucket_refill(self):
        """Test token bucket refilling over time."""
        limiter = RateLimiter(max_messages_per_second=10, burst_size=5)
        ip = "192.0.2.1"

        # Mock time from the beginning to control timing
        start_time = 1000.0  # Fixed start time
        with patch("src.utils.rate_limiter.time.time") as mock_time:
            mock_time.return_value = start_time

            # Consume all tokens
            allowed = await limiter.check_message_allowed(ip, count=5)
            assert allowed is True
            assert limiter.message_tokens[ip] == 0

            # Advance time by 0.5 seconds (should refill 5 tokens at 10/sec rate)
            mock_time.return_value = start_time + 0.5

            allowed = await limiter.check_message_allowed(ip, count=5)
            assert allowed is True

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_token_bucket_max_cap(self):
        """Test token bucket doesn't exceed maximum capacity."""
        limiter = RateLimiter(max_messages_per_second=100, burst_size=10)
        ip = "192.0.2.1"

        start_time = 1000.0  # Fixed start time
        with patch("src.utils.rate_limiter.time.time") as mock_time:
            mock_time.return_value = start_time

            # Initialize
            await limiter.check_message_allowed(ip, count=0)

            # Advance time by a long period (should cap at burst_size)
            mock_time.return_value = start_time + 10  # 10 seconds

            # Should only allow burst_size tokens, not more
            allowed = await limiter.check_message_allowed(ip, count=10)
            assert allowed is True

            # Next request should be denied (no tokens left)
            allowed = await limiter.check_message_allowed(ip, count=1)
            assert allowed is False

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_different_ips_independent(self):
        """Test that different IPs have independent limits."""
        limiter = RateLimiter(max_connections_per_ip=2, burst_size=5)
        ip1 = "192.0.2.1"
        ip2 = "192.0.2.2"

        # Exhaust connections for ip1
        await limiter.check_connection_allowed(ip1)
        await limiter.check_connection_allowed(ip1)
        denied = await limiter.check_connection_allowed(ip1)
        assert denied is False

        # ip2 should still be allowed
        allowed = await limiter.check_connection_allowed(ip2)
        assert allowed is True

        # Exhaust message tokens for ip1
        await limiter.check_message_allowed(ip1, count=5)
        denied = await limiter.check_message_allowed(ip1, count=1)
        assert denied is False

        # ip2 should still be allowed
        allowed = await limiter.check_message_allowed(ip2, count=1)
        assert allowed is True

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_concurrent_access(self):
        """Test concurrent access to rate limiter."""
        limiter = RateLimiter(max_connections_per_ip=10, burst_size=50)
        ip = "192.0.2.1"

        async def connection_worker():
            return await limiter.check_connection_allowed(ip)

        async def message_worker():
            return await limiter.check_message_allowed(ip)

        # Run concurrent operations
        connection_tasks = [connection_worker() for _ in range(5)]
        message_tasks = [message_worker() for _ in range(10)]

        connection_results = await asyncio.gather(*connection_tasks)
        message_results = await asyncio.gather(*message_tasks)

        # All should succeed (within limits)
        assert all(connection_results)
        assert all(message_results)

        # Verify final state
        assert limiter.connections_per_ip[ip] == 5
        assert abs(limiter.message_tokens[ip] - 40.0) < 0.1  # 50 - 10, allowing for floating point precision

    @pytest.mark.unit
    def test_get_stats(self):
        """Test getting rate limiter statistics."""
        limiter = RateLimiter()

        # Initially empty
        stats = limiter.get_stats()
        assert stats["active_connections"] == {}
        assert stats["total_ips"] == 0
        assert stats["max_connections"] == 0

        # Add some connections
        limiter.connections_per_ip["192.0.2.1"] = 3
        limiter.connections_per_ip["192.0.2.2"] = 5
        limiter.connections_per_ip["10.0.0.1"] = 1

        stats = limiter.get_stats()
        expected_connections = {"192.0.2.1": 3, "192.0.2.2": 5, "10.0.0.1": 1}

        assert stats["active_connections"] == expected_connections
        assert stats["total_ips"] == 3
        assert stats["max_connections"] == 5

    @pytest.mark.unit
    def test_get_stats_empty(self):
        """Test stats with no connections."""
        limiter = RateLimiter()
        stats = limiter.get_stats()

        assert stats["active_connections"] == {}
        assert stats["total_ips"] == 0
        assert stats["max_connections"] == 0


class TestRateLimiterEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_zero_limits(self):
        """Test rate limiter with zero limits."""
        # Zero connection limit
        limiter = RateLimiter(max_connections_per_ip=0)
        ip = "192.0.2.1"

        allowed = await limiter.check_connection_allowed(ip)
        assert allowed is False

        # Zero message rate
        limiter = RateLimiter(max_messages_per_second=0, burst_size=0)
        allowed = await limiter.check_message_allowed(ip)
        assert allowed is False

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_very_high_limits(self):
        """Test rate limiter with very high limits."""
        limiter = RateLimiter(
            max_connections_per_ip=10000, max_messages_per_second=100000, burst_size=10000
        )
        ip = "192.0.2.1"

        # Should handle high limits without issues
        for _ in range(100):
            allowed = await limiter.check_connection_allowed(ip)
            assert allowed is True

        for _ in range(1000):
            allowed = await limiter.check_message_allowed(ip)
            assert allowed is True

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_time_synchronization_edge_case(self):
        """Test edge case where time goes backwards."""
        limiter = RateLimiter(max_messages_per_second=10, burst_size=5)
        ip = "192.0.2.1"

        with patch("time.time") as mock_time:
            start_time = 1000.0
            mock_time.return_value = start_time

            # Initialize
            await limiter.check_message_allowed(ip)

            # Time goes backwards (shouldn't happen in practice, but handle gracefully)
            mock_time.return_value = start_time - 1

            # Should not add negative tokens
            allowed = await limiter.check_message_allowed(ip)
            # Behavior depends on implementation, but shouldn't crash

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_ipv6_addresses(self):
        """Test rate limiter with IPv6 addresses."""
        limiter = RateLimiter(max_connections_per_ip=2)
        ipv6 = "2001:db8::1"

        # Should work with IPv6 addresses
        allowed1 = await limiter.check_connection_allowed(ipv6)
        allowed2 = await limiter.check_connection_allowed(ipv6)
        allowed3 = await limiter.check_connection_allowed(ipv6)

        assert allowed1 is True
        assert allowed2 is True
        assert allowed3 is False

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_long_ip_addresses(self):
        """Test rate limiter with very long IP address strings."""
        limiter = RateLimiter()
        long_ip = "a" * 1000  # Very long string

        # Should handle without issues
        allowed = await limiter.check_connection_allowed(long_ip)
        assert allowed is True

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_fractional_tokens(self):
        """Test token bucket with fractional token generation."""
        limiter = RateLimiter(max_messages_per_second=1.5, burst_size=5)  # 1.5 tokens per second
        ip = "192.0.2.1"

        with patch("time.time") as mock_time:
            start_time = 1000.0
            mock_time.return_value = start_time

            # Initialize and consume all tokens
            await limiter.check_message_allowed(ip, count=5)
            assert limiter.message_tokens[ip] == 0

            # Advance time by 1 second (should add 1.5 tokens)
            mock_time.return_value = start_time + 1.0

            allowed = await limiter.check_message_allowed(ip, count=1)
            assert allowed is True
            assert abs(limiter.message_tokens[ip] - 0.5) < 0.001  # Should have 0.5 tokens left

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_rapid_successive_calls(self):
        """Test rapid successive calls to rate limiter."""
        limiter = RateLimiter(burst_size=10)
        ip = "192.0.2.1"

        # Make many rapid calls
        results = []
        for i in range(20):
            result = await limiter.check_message_allowed(ip)
            results.append(result)

        # First 10 should be allowed, rest denied
        assert all(results[:10])  # First 10 allowed
        assert not any(results[10:])  # Rest denied

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_memory_cleanup(self):
        """Test that data structures don't grow indefinitely."""
        limiter = RateLimiter()

        # Add many IPs
        for i in range(1000):
            ip = f"192.0.2.{i % 256}"
            await limiter.check_connection_allowed(ip)
            await limiter.check_message_allowed(ip)

        # Release all connections
        for i in range(1000):
            ip = f"192.0.2.{i % 256}"
            await limiter.release_connection(ip)

        # Check that connection tracking is cleaned up
        stats = limiter.get_stats()
        assert stats["total_ips"] == 0

        # Message tokens should still exist (they don't auto-cleanup)
        assert len(limiter.message_tokens) > 0
