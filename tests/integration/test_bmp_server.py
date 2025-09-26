"""Integration tests for BMP server functionality."""
import pytest
import asyncio
import struct
from unittest.mock import AsyncMock, patch
from datetime import datetime

from src.bmp.server import BMPServer, BMPSession
from src.bmp.processor import RouteProcessor
from tests.fixtures.bmp_messages import TEST_MESSAGES, BMPMessageBuilder


class TestBMPSession:
    """Test BMP session functionality."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_session_initialization(self, test_settings, mock_db_pool):
        """Test BMP session initialization."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        session = BMPSession(reader, writer, router_ip, processor)

        assert session.router_ip == router_ip
        assert session.processor == processor
        assert session.messages_received == 0
        assert session.buffer == b""
        assert isinstance(session.connected_at, datetime)

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_session_handle_single_message(self, test_settings, mock_db_pool):
        """Test handling single BMP message."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Mock reader to return a complete BMP message then EOF
        test_message = TEST_MESSAGES['route_monitoring']
        reader.read.side_effect = [test_message, b""]  # Message then EOF

        session = BMPSession(reader, writer, router_ip, processor)

        await session.handle()

        # Verify message was processed
        assert session.messages_received == 1
        mock_db_pool.batch_insert_routes.assert_called()

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_session_handle_multiple_messages(self, test_settings, mock_db_pool):
        """Test handling multiple BMP messages in sequence."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Mock reader to return multiple messages
        messages = [
            TEST_MESSAGES['initiation'],
            TEST_MESSAGES['peer_up'],
            TEST_MESSAGES['route_monitoring'],
            b""  # EOF
        ]
        reader.read.side_effect = messages

        session = BMPSession(reader, writer, router_ip, processor)

        await session.handle()

        # Verify all messages were processed
        assert session.messages_received == 3

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_session_handle_fragmented_message(self, test_settings, mock_db_pool):
        """Test handling fragmented BMP message."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Split a message into fragments
        test_message = TEST_MESSAGES['route_monitoring']
        fragment1 = test_message[:20]
        fragment2 = test_message[20:]

        reader.read.side_effect = [fragment1, fragment2, b""]  # Fragments then EOF

        session = BMPSession(reader, writer, router_ip, processor)

        await session.handle()

        # Should successfully reassemble and process the message
        assert session.messages_received == 1

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_session_buffer_overflow_protection(self, test_settings, mock_db_pool):
        """Test buffer overflow protection."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Create oversized data that would exceed buffer limit
        oversized_data = b'x' * (BMPSession.MAX_BUFFER_SIZE + 1000)
        reader.read.side_effect = [oversized_data]

        session = BMPSession(reader, writer, router_ip, processor)

        with patch('src.bmp.server.logger') as mock_logger:
            await session.handle()

            # Should log buffer overflow and terminate
            mock_logger.error.assert_called()
            assert "Buffer overflow protection triggered" in str(mock_logger.error.call_args)

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_session_invalid_bmp_version(self, test_settings, mock_db_pool):
        """Test handling invalid BMP version."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Create message with invalid BMP version
        invalid_message = b'\x99' + b'\x00\x00\x00\x10' + b'\x00' + b'test'
        reader.read.side_effect = [invalid_message, b""]

        session = BMPSession(reader, writer, router_ip, processor)

        with patch('src.bmp.server.logger') as mock_logger:
            await session.handle()

            # Should log warning and skip the invalid byte
            mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_session_oversized_message(self, test_settings, mock_db_pool):
        """Test handling oversized individual message."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Create message header claiming oversized length
        oversized_header = struct.pack(">BIB", 3, BMPSession.MAX_MESSAGE_SIZE + 1000, 0)
        reader.read.side_effect = [oversized_header, b""]

        session = BMPSession(reader, writer, router_ip, processor)

        with patch('src.bmp.server.logger') as mock_logger:
            await session.handle()

            # Should log error and clear buffer
            mock_logger.error.assert_called()
            assert "Message too large" in str(mock_logger.error.call_args)

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_session_close(self, test_settings, mock_db_pool):
        """Test session closure."""
        reader = AsyncMock()
        writer = AsyncMock()
        writer.wait_closed = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        session = BMPSession(reader, writer, router_ip, processor)

        await session.close()

        # Verify cleanup operations
        processor.flush_routes.assert_called_once()
        writer.close.assert_called_once()
        writer.wait_closed.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_session_exception_handling(self, test_settings, mock_db_pool):
        """Test session exception handling."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Mock reader to raise exception
        reader.read.side_effect = Exception("Network error")

        session = BMPSession(reader, writer, router_ip, processor)

        with patch('src.bmp.server.logger') as mock_logger:
            await session.handle()

            # Should log error and handle gracefully
            mock_logger.error.assert_called()


class TestBMPServer:
    """Test BMP server functionality."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_server_initialization(self, test_settings, mock_db_pool):
        """Test BMP server initialization."""
        server = BMPServer(test_settings, mock_db_pool)

        assert server.settings == test_settings
        assert server.db_pool == mock_db_pool
        assert isinstance(server.processor, RouteProcessor)
        assert len(server.sessions) == 0
        assert server.server is None

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_server_start_stop(self, test_settings, mock_db_pool):
        """Test server start and stop."""
        server = BMPServer(test_settings, mock_db_pool)

        # Mock asyncio.start_server
        mock_server = AsyncMock()
        mock_server.sockets = [AsyncMock()]
        mock_server.sockets[0].getsockname.return_value = ('127.0.0.1', 11019)
        mock_server.serve_forever = AsyncMock()
        mock_server.close = AsyncMock()
        mock_server.wait_closed = AsyncMock()

        with patch('asyncio.start_server', return_value=mock_server):
            with patch('asyncio.create_task') as mock_create_task:
                mock_task = AsyncMock()
                mock_create_task.return_value = mock_task

                # Start server (but don't wait for serve_forever)
                start_task = asyncio.create_task(server.start())

                # Give it a moment to initialize
                await asyncio.sleep(0.01)

                # Stop server
                await server.stop()

                # Cancel the start task
                start_task.cancel()
                try:
                    await start_task
                except asyncio.CancelledError:
                    pass

                # Verify cleanup
                mock_server.close.assert_called_once()
                mock_server.wait_closed.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_server_handle_client(self, test_settings, mock_db_pool):
        """Test server handling new client connection."""
        server = BMPServer(test_settings, mock_db_pool)

        reader = AsyncMock()
        writer = AsyncMock()
        writer.get_extra_info.return_value = ('192.0.2.1', 12345)

        # Mock session handling
        with patch.object(BMPSession, 'handle') as mock_handle:
            mock_handle.return_value = asyncio.create_task(asyncio.sleep(0))

            await server._handle_client(reader, writer)

            # Verify session was created and handled
            mock_handle.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_server_connection_limit(self, test_settings, mock_db_pool):
        """Test server connection limit enforcement."""
        test_settings.bmp_max_connections = 1
        server = BMPServer(test_settings, mock_db_pool)

        # Add existing session to reach limit
        server.sessions['192.0.2.1'] = AsyncMock()

        reader = AsyncMock()
        writer = AsyncMock()
        writer.get_extra_info.return_value = ('192.0.2.2', 12345)
        writer.close = AsyncMock()
        writer.wait_closed = AsyncMock()

        with patch('src.bmp.server.logger') as mock_logger:
            await server._handle_client(reader, writer)

            # Should reject connection and log warning
            mock_logger.warning.assert_called()
            writer.close.assert_called_once()
            writer.wait_closed.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_server_periodic_flush(self, test_settings, mock_db_pool):
        """Test server periodic flush functionality."""
        test_settings.batch_timeout_seconds = 0.01  # Very short for testing
        server = BMPServer(test_settings, mock_db_pool)
        server._running = True

        # Mock processor stats
        server.processor.get_stats.return_value = {
            'messages_processed': 100,
            'routes_processed': 500,
            'withdrawals_processed': 25,
            'errors': 2
        }

        with patch('src.bmp.server.logger') as mock_logger:
            # Run flush for a short time
            flush_task = asyncio.create_task(server._periodic_flush())
            await asyncio.sleep(0.05)  # Let it run briefly
            server._running = False

            try:
                await flush_task
            except asyncio.CancelledError:
                pass

            # Verify flush was called and stats were logged
            server.processor.flush_routes.assert_called()
            mock_logger.info.assert_called()

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_server_periodic_cleanup(self, test_settings, mock_db_pool):
        """Test server periodic cleanup functionality."""
        test_settings.cleanup_interval_hours = 0.001  # Very short for testing
        test_settings.data_retention_days = 30
        server = BMPServer(test_settings, mock_db_pool)
        server._running = True

        # Mock cleanup result
        mock_db_pool.cleanup_old_data.return_value = 150

        with patch('src.bmp.server.logger') as mock_logger:
            # Run cleanup for a short time
            cleanup_task = asyncio.create_task(server._periodic_cleanup())
            await asyncio.sleep(0.01)  # Let it run briefly
            server._running = False

            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass

            # Verify cleanup was called
            mock_db_pool.cleanup_old_data.assert_called_with(30)

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_server_get_active_sessions(self, test_settings, mock_db_pool):
        """Test getting active session information."""
        server = BMPServer(test_settings, mock_db_pool)

        # Create mock sessions
        session1 = AsyncMock()
        session1.connected_at = datetime(2024, 1, 1, 12, 0, 0)
        session1.last_message = datetime(2024, 1, 1, 12, 30, 0)
        session1.messages_received = 100

        session2 = AsyncMock()
        session2.connected_at = datetime(2024, 1, 1, 13, 0, 0)
        session2.last_message = datetime(2024, 1, 1, 13, 15, 0)
        session2.messages_received = 50

        server.sessions['192.0.2.1'] = session1
        server.sessions['192.0.2.2'] = session2

        sessions_info = server.get_active_sessions()

        assert len(sessions_info) == 2
        assert '192.0.2.1' in sessions_info
        assert '192.0.2.2' in sessions_info
        assert sessions_info['192.0.2.1']['messages_received'] == 100
        assert sessions_info['192.0.2.2']['messages_received'] == 50

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_server_session_cleanup_on_error(self, test_settings, mock_db_pool):
        """Test session cleanup when client handling fails."""
        server = BMPServer(test_settings, mock_db_pool)

        reader = AsyncMock()
        writer = AsyncMock()
        writer.get_extra_info.return_value = ('192.0.2.1', 12345)

        # Mock session to raise exception
        with patch.object(BMPSession, 'handle') as mock_handle:
            mock_handle.side_effect = Exception("Session error")

            with patch('src.bmp.server.logger'):
                await server._handle_client(reader, writer)

            # Session should be cleaned up even after error
            assert '192.0.2.1' not in server.sessions


class TestBMPServerIntegrationScenarios:
    """Test realistic integration scenarios."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_full_session_lifecycle(self, test_settings, mock_db_pool):
        """Test complete session lifecycle with realistic message flow."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Simulate realistic message sequence
        messages = [
            TEST_MESSAGES['initiation'],
            TEST_MESSAGES['peer_up'],
            TEST_MESSAGES['route_monitoring'],
            TEST_MESSAGES['stats_report'],
            TEST_MESSAGES['peer_down'],
            TEST_MESSAGES['termination'],
            b""  # EOF
        ]
        reader.read.side_effect = messages

        session = BMPSession(reader, writer, router_ip, processor)

        await session.handle()

        # Verify all message types were processed
        assert session.messages_received == 6

        # Verify database interactions
        mock_db_pool.create_or_update_session.assert_called()
        mock_db_pool.batch_insert_routes.assert_called()
        mock_db_pool.update_statistics.assert_called()

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_concurrent_sessions(self, test_settings, mock_db_pool):
        """Test handling multiple concurrent sessions."""
        server = BMPServer(test_settings, mock_db_pool)

        # Create multiple mock client connections
        clients = []
        for i in range(3):
            reader = AsyncMock()
            writer = AsyncMock()
            writer.get_extra_info.return_value = (f'192.0.2.{i+1}', 12345)

            # Each client sends one message then disconnects
            reader.read.side_effect = [TEST_MESSAGES['route_monitoring'], b""]
            clients.append((reader, writer))

        # Handle all clients concurrently
        tasks = []
        for reader, writer in clients:
            task = asyncio.create_task(server._handle_client(reader, writer))
            tasks.append(task)

        await asyncio.gather(*tasks)

        # All sessions should have been processed and cleaned up
        assert len(server.sessions) == 0

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_message_processing_pipeline(self, test_settings, mock_db_pool):
        """Test end-to-end message processing pipeline."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Create a route monitoring message with multiple routes
        route_monitoring = BMPMessageBuilder.create_route_monitoring_message(
            nlri=['10.0.1.0/24', '10.0.2.0/24', '10.0.3.0/24']
        )

        reader.read.side_effect = [route_monitoring, b""]

        session = BMPSession(reader, writer, router_ip, processor)

        await session.handle()

        # Verify processing pipeline
        assert session.messages_received == 1
        assert len(processor.route_buffer) == 3  # Three routes buffered

        # Trigger flush
        await processor.flush_routes()

        # Verify database operations
        mock_db_pool.batch_insert_routes.assert_called()
        # Should have one call with 3 routes
        call_args = mock_db_pool.batch_insert_routes.call_args[0][0]
        assert len(call_args) == 3

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_error_recovery(self, test_settings, mock_db_pool):
        """Test error recovery during message processing."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Mix valid and invalid messages
        invalid_message = b'\x03' + b'\x00\x00\x00\x08' + b'\x99\x00'  # Invalid message type
        valid_message = TEST_MESSAGES['route_monitoring']

        reader.read.side_effect = [invalid_message, valid_message, b""]

        session = BMPSession(reader, writer, router_ip, processor)

        with patch('src.bmp.server.logger'):
            await session.handle()

        # Should process valid message despite invalid one
        assert session.messages_received == 1  # Only valid message counted

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_high_throughput_scenario(self, test_settings, mock_db_pool):
        """Test high throughput message processing."""
        reader = AsyncMock()
        writer = AsyncMock()
        router_ip = "192.0.2.1"
        processor = RouteProcessor(mock_db_pool)

        # Generate many route monitoring messages
        messages = []
        for i in range(50):  # 50 messages
            msg = BMPMessageBuilder.create_route_monitoring_message(
                nlri=[f'10.{i}.0.0/16']
            )
            messages.append(msg)
        messages.append(b"")  # EOF

        reader.read.side_effect = messages

        session = BMPSession(reader, writer, router_ip, processor)

        await session.handle()

        # Verify all messages processed
        assert session.messages_received == 50

        # Verify route buffer management (should auto-flush)
        assert mock_db_pool.batch_insert_routes.call_count > 0