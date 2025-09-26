"""Rate limiting for BMP connections."""
import asyncio
import time
from collections import defaultdict
from typing import Dict, Optional


class RateLimiter:
    """Simple rate limiter for connection and message throttling."""

    def __init__(self, max_connections_per_ip: int = 10,
                 max_messages_per_second: int = 1000,
                 burst_size: int = 100):
        self.max_connections_per_ip = max_connections_per_ip
        self.max_messages_per_second = max_messages_per_second
        self.burst_size = burst_size

        # Connection tracking
        self.connections_per_ip: Dict[str, int] = defaultdict(int)

        # Message rate tracking using token bucket
        self.message_tokens: Dict[str, float] = defaultdict(lambda: burst_size)
        self.last_update: Dict[str, float] = defaultdict(time.time)
        self._lock = asyncio.Lock()

    async def check_connection_allowed(self, ip: str) -> bool:
        """Check if a new connection from this IP is allowed."""
        async with self._lock:
            if self.connections_per_ip[ip] >= self.max_connections_per_ip:
                return False
            self.connections_per_ip[ip] += 1
            return True

    async def release_connection(self, ip: str) -> None:
        """Release a connection slot for an IP."""
        async with self._lock:
            if ip in self.connections_per_ip:
                self.connections_per_ip[ip] = max(0, self.connections_per_ip[ip] - 1)
                if self.connections_per_ip[ip] == 0:
                    del self.connections_per_ip[ip]

    async def check_message_allowed(self, ip: str, count: int = 1) -> bool:
        """Check if messages from this IP are allowed (token bucket algorithm)."""
        async with self._lock:
            now = time.time()
            time_passed = now - self.last_update[ip]

            # Refill tokens based on time passed
            tokens_to_add = time_passed * self.max_messages_per_second
            self.message_tokens[ip] = min(
                self.burst_size,
                self.message_tokens[ip] + tokens_to_add
            )
            self.last_update[ip] = now

            # Check if we have enough tokens
            if self.message_tokens[ip] >= count:
                self.message_tokens[ip] -= count
                return True
            return False

    def get_stats(self) -> Dict[str, any]:
        """Get current rate limiter statistics."""
        return {
            'active_connections': dict(self.connections_per_ip),
            'total_ips': len(self.connections_per_ip),
            'max_connections': max(self.connections_per_ip.values()) if self.connections_per_ip else 0
        }