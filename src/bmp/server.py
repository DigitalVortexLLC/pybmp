import asyncio
import logging
from typing import Dict, Optional, Set
from datetime import datetime, timezone

from src.bmp.parser import BMPParser
from src.bmp.processor import RouteProcessor
from src.database.connection import DatabasePool
from src.utils.config import Settings

logger = logging.getLogger(__name__)


class BMPSession:
    """Represents a BMP session with a router."""

    MAX_BUFFER_SIZE = 10 * 1024 * 1024  # 10MB buffer limit
    MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB max message size

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        router_ip: str,
        processor: RouteProcessor,
    ):
        self.reader = reader
        self.writer = writer
        self.router_ip = router_ip
        self.processor = processor
        self.parser = BMPParser()
        self.session_id = None
        self.connected_at = datetime.now(timezone.utc)
        self.last_message = datetime.now(timezone.utc)
        self.messages_received = 0
        self.buffer = b""

    async def handle(self) -> None:
        """Handle incoming BMP messages from the router."""
        try:
            logger.info(f"BMP session established with {self.router_ip}")

            while True:
                # Read data from socket
                data = await self.reader.read(65536)
                if not data:
                    break

                # Check buffer size limit to prevent memory exhaustion
                if len(self.buffer) + len(data) > self.MAX_BUFFER_SIZE:
                    logger.error(f"Buffer overflow protection triggered for {self.router_ip}")
                    break

                self.buffer += data
                self.last_message = datetime.now(timezone.utc)

                # Process complete messages from buffer
                while len(self.buffer) >= 6:
                    # Check if we have a complete message
                    if self.buffer[0] != 3:  # BMP version check
                        logger.warning(f"Invalid BMP version from {self.router_ip}")
                        self.buffer = self.buffer[1:]  # Skip byte and continue
                        continue

                    msg_length = int.from_bytes(self.buffer[1:5], "big")

                    # Validate message length
                    if msg_length > self.MAX_MESSAGE_SIZE:
                        logger.error(
                            f"Message too large ({msg_length} bytes) from {self.router_ip}"
                        )
                        self.buffer = b""  # Clear buffer to recover
                        break

                    if len(self.buffer) < msg_length:
                        # Wait for more data
                        break

                    # Extract and process complete message
                    msg_data = self.buffer[:msg_length]
                    self.buffer = self.buffer[msg_length:]

                    # Parse BMP message
                    message = self.parser.parse_message(msg_data)
                    if message:
                        await self.processor.process_message(message, self.router_ip)
                        self.messages_received += 1

                        # Log every 100th message
                        if self.messages_received % 100 == 0:
                            logger.debug(
                                f"Processed {self.messages_received} messages from {self.router_ip}"
                            )

        except asyncio.CancelledError:
            logger.info(f"BMP session with {self.router_ip} cancelled")
        except Exception as e:
            logger.error(f"Error in BMP session with {self.router_ip}: {e}")
        finally:
            await self.close()

    async def close(self) -> None:
        """Close the BMP session."""
        try:
            # Flush any remaining routes
            await self.processor.flush_routes()

            # Close the connection
            self.writer.close()
            await self.writer.wait_closed()

            logger.info(
                f"BMP session with {self.router_ip} closed. Messages: {self.messages_received}"
            )
        except Exception as e:
            logger.error(f"Error closing session with {self.router_ip}: {e}")


class BMPServer:
    """BMP server to accept connections from routers."""

    def __init__(self, settings: Settings, db_pool: DatabasePool):
        self.settings = settings
        self.db_pool = db_pool
        self.processor = RouteProcessor(db_pool)
        self.sessions: Dict[str, BMPSession] = {}
        self.server = None
        self._running = False
        self._flush_task = None
        self._cleanup_task = None

    async def start(self) -> None:
        """Start the BMP server."""
        try:
            self.server = await asyncio.start_server(
                self._handle_client, self.settings.bmp_listen_host, self.settings.bmp_listen_port
            )

            self._running = True

            # Start background tasks
            self._flush_task = asyncio.create_task(self._periodic_flush())
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup())

            addr = self.server.sockets[0].getsockname()
            logger.info(f"BMP server listening on {addr[0]}:{addr[1]}")

            async with self.server:
                await self.server.serve_forever()

        except Exception as e:
            logger.error(f"Failed to start BMP server: {e}")
            raise

    async def stop(self) -> None:
        """Stop the BMP server."""
        self._running = False

        # Cancel background tasks
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Close all sessions
        for session in list(self.sessions.values()):
            await session.close()

        # Stop the server
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        logger.info("BMP server stopped")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a new client connection."""
        try:
            addr = writer.get_extra_info("peername")
            # Handle case where get_extra_info returns a coroutine (in tests)
            if hasattr(addr, '__await__'):
                addr = await addr
            router_ip = addr[0] if addr else "unknown"
        except (TypeError, IndexError, AttributeError):
            router_ip = "unknown"

        try:
            # Check connection limit
            if len(self.sessions) >= self.settings.bmp_max_connections:
                logger.warning(f"Connection limit reached, rejecting {router_ip}")
                writer.close()
                await writer.wait_closed()
                return

            # Create new session
            session = BMPSession(reader, writer, router_ip, self.processor)
            self.sessions[router_ip] = session

            # Handle the session
            await session.handle()

        except Exception as e:
            logger.error(f"Error handling client {router_ip}: {e}")
        finally:
            # Remove session
            if router_ip in self.sessions:
                del self.sessions[router_ip]

    async def _periodic_flush(self) -> None:
        """Periodically flush buffered routes to database."""
        while self._running:
            try:
                await asyncio.sleep(self.settings.batch_timeout_seconds)
                await self.processor.flush_routes()

                # Log statistics
                stats = self.processor.get_stats()
                logger.info(
                    f"BMP Stats - Messages: {stats['messages_processed']}, "
                    f"Routes: {stats['routes_processed']}, "
                    f"Withdrawals: {stats['withdrawals_processed']}, "
                    f"Errors: {stats['errors']}"
                )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic flush: {e}")

    async def _periodic_cleanup(self) -> None:
        """Periodically cleanup old data based on retention policy."""
        while self._running:
            try:
                # Wait for cleanup interval
                await asyncio.sleep(self.settings.cleanup_interval_hours * 3600)

                # Cleanup old data
                deleted = await self.db_pool.cleanup_old_data(self.settings.data_retention_days)
                logger.info(f"Cleaned up {deleted} old records")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic cleanup: {e}")

    def get_active_sessions(self) -> Dict[str, Dict]:
        """Get information about active sessions."""
        sessions_info = {}
        for router_ip, session in self.sessions.items():
            sessions_info[router_ip] = {
                "connected_at": session.connected_at.isoformat(),
                "last_message": session.last_message.isoformat(),
                "messages_received": session.messages_received,
            }
        return sessions_info
