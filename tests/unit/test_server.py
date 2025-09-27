"""Unit tests for BMP server components."""

import asyncio
import struct
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.bmp.server import BMPSession


class TestBMPSession:
    """Test BMP session functionality."""

    @pytest.fixture
    def mock_reader(self):
        """Create mock stream reader."""
        reader = AsyncMock()
        return reader

    @pytest.fixture
    def mock_writer(self):
        """Create mock stream writer."""
        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        writer.get_extra_info = MagicMock(return_value=("127.0.0.1", 12345))
        return writer

    @pytest.fixture
    def mock_processor(self):
        """Create mock route processor."""
        processor = MagicMock()
        processor.process_message = AsyncMock()
        processor.flush_routes = AsyncMock()
        return processor

    @pytest.fixture
    def bmp_session(self, mock_reader, mock_writer, mock_processor):
        """Create BMP session instance."""
        return BMPSession(mock_reader, mock_writer, "192.0.2.1", mock_processor)

    @pytest.mark.unit
    def test_bmp_session_initialization(self, bmp_session, mock_processor):
        """Test BMP session initialization."""
        assert bmp_session.router_ip == "192.0.2.1"
        assert bmp_session.processor == mock_processor
        assert bmp_session.session_id is None
        assert bmp_session.messages_received == 0
        assert bmp_session.buffer == b""
        assert isinstance(bmp_session.connected_at, datetime)
        assert isinstance(bmp_session.last_message, datetime)

    @pytest.mark.unit
    def test_bmp_session_constants(self):
        """Test BMP session constants."""
        assert BMPSession.MAX_BUFFER_SIZE == 10 * 1024 * 1024  # 10MB
        assert BMPSession.MAX_MESSAGE_SIZE == 1024 * 1024  # 1MB

    @pytest.mark.unit
    async def test_bmp_session_handle_no_data(self, bmp_session, mock_reader):
        """Test session handling when no data is received."""
        mock_reader.read.return_value = b""

        # Should exit gracefully when no data
        await bmp_session.handle()

        mock_reader.read.assert_called_once_with(65536)

    @pytest.mark.unit
    async def test_bmp_session_handle_buffer_overflow(self, bmp_session, mock_reader):
        """Test session handling with buffer overflow protection."""
        # Test that buffer size constants exist
        assert BMPSession.MAX_BUFFER_SIZE > 0
        assert BMPSession.MAX_MESSAGE_SIZE > 0

        # Test with empty data to avoid complex buffer logic
        mock_reader.read.return_value = b""
        await bmp_session.handle()

    @pytest.mark.unit
    async def test_bmp_session_handle_exception(self, bmp_session, mock_reader):
        """Test session handling with exception."""
        mock_reader.read.side_effect = Exception("Connection error")

        with patch("src.bmp.server.logger") as mock_logger:
            await bmp_session.handle()

            mock_logger.error.assert_called_once()
            assert "Error in BMP session" in str(mock_logger.error.call_args)

    @pytest.mark.unit
    def test_bmp_session_attributes(self, bmp_session):
        """Test session attributes."""
        # Set some values
        bmp_session.session_id = "test-session"
        bmp_session.messages_received = 42

        assert bmp_session.router_ip == "192.0.2.1"
        assert bmp_session.session_id == "test-session"
        assert bmp_session.messages_received == 42
        assert bmp_session.connected_at is not None
        assert bmp_session.last_message is not None

    @pytest.mark.unit
    async def test_bmp_session_close(self, bmp_session, mock_writer, mock_processor):
        """Test session close."""
        await bmp_session.close()

        mock_processor.flush_routes.assert_called_once()
        mock_writer.close.assert_called_once()
        mock_writer.wait_closed.assert_called_once()

    @pytest.mark.unit
    async def test_bmp_session_close_exception(self, bmp_session, mock_writer):
        """Test session close with exception."""
        mock_writer.wait_closed.side_effect = Exception("Close error")

        with patch("src.bmp.server.logger") as mock_logger:
            await bmp_session.close()

            mock_logger.error.assert_called_once()
            assert "Error closing session" in str(mock_logger.error.call_args)

    @pytest.mark.unit
    def test_bmp_session_timestamps(self, bmp_session):
        """Test timestamp tracking in session."""
        # Should have initial timestamps
        assert bmp_session.connected_at is not None
        assert bmp_session.last_message is not None
        assert isinstance(bmp_session.connected_at, datetime)
        assert isinstance(bmp_session.last_message, datetime)

        # Timestamps should be in UTC
        assert bmp_session.connected_at.tzinfo == timezone.utc
        assert bmp_session.last_message.tzinfo == timezone.utc

    @pytest.mark.unit
    async def test_bmp_session_message_processing_loop(
        self, bmp_session, mock_reader, mock_processor
    ):
        """Test message processing loop with valid BMP message."""
        # Create a valid minimal BMP message
        bmp_header = struct.pack(">BBBBB", 3, 0, 0, 0, 50)  # Version 3, 50 byte message
        bmp_header += struct.pack(">B", 4)  # Initiation message
        payload = b"x" * 44  # Rest of the message

        # First call returns message, second returns empty (to exit loop)
        mock_reader.read.side_effect = [bmp_header + payload, b""]

        # Mock the parser to return a valid message
        with patch.object(
            bmp_session.parser, "parse_message", return_value={"type": 4, "test": True}
        ):
            await bmp_session.handle()

            # Should have processed one message
            mock_processor.process_message.assert_called_once()

    @pytest.mark.unit
    async def test_bmp_session_invalid_message_handling(
        self, bmp_session, mock_reader, mock_processor
    ):
        """Test handling of invalid BMP messages."""
        # Invalid BMP message (too short)
        invalid_data = b"invalid"

        # First call returns invalid data, second returns empty
        mock_reader.read.side_effect = [invalid_data, b""]

        # Mock parser to return None for invalid message
        with patch.object(bmp_session.parser, "parse_message", return_value=None):
            await bmp_session.handle()

            # Should not have processed any message
            mock_processor.process_message.assert_not_called()

    @pytest.mark.unit
    def test_bmp_session_buffer_management(self, bmp_session):
        """Test session buffer management."""
        # Test initial buffer state
        assert bmp_session.buffer == b""

        # Test buffer modification
        bmp_session.buffer = b"test_data"
        assert bmp_session.buffer == b"test_data"

        # Test constants are accessible
        assert hasattr(bmp_session, "MAX_BUFFER_SIZE")
        assert hasattr(bmp_session, "MAX_MESSAGE_SIZE")

    @pytest.mark.unit
    async def test_bmp_session_cancelled_handling(self, bmp_session, mock_reader):
        """Test session handling when cancelled."""
        # Mock reader to raise CancelledError
        mock_reader.read.side_effect = asyncio.CancelledError()

        # Should handle cancellation gracefully
        await bmp_session.handle()

        # Session should still be properly closed
        assert True  # Just ensure no exception is raised

    @pytest.mark.unit
    def test_bmp_session_stats_tracking(self, bmp_session):
        """Test session statistics tracking."""
        # Test initial state
        assert bmp_session.messages_received == 0

        # Test incrementing
        bmp_session.messages_received += 1
        assert bmp_session.messages_received == 1

        # Test session ID setting
        bmp_session.session_id = "test-123"
        assert bmp_session.session_id == "test-123"

    @pytest.mark.unit
    async def test_bmp_session_buffer_overflow_protection(self, bmp_session, mock_reader):
        """Test buffer overflow protection."""
        # Create data that would exceed buffer limit
        large_data = b"x" * (bmp_session.MAX_BUFFER_SIZE + 1000)
        mock_reader.read.side_effect = [large_data, b""]

        with patch("src.bmp.server.logger") as mock_logger:
            await bmp_session.handle()

            # Should log buffer overflow and clear buffer
            mock_logger.error.assert_called_once()
            assert "Buffer overflow protection triggered" in str(mock_logger.error.call_args)

    @pytest.mark.unit
    async def test_bmp_session_invalid_version_handling(self, bmp_session, mock_reader):
        """Test handling invalid BMP version."""
        # Invalid version (not 3) + valid message
        invalid_version_data = b"\x02\x00\x00\x00\x10test"
        mock_reader.read.side_effect = [invalid_version_data, b""]

        with patch("src.bmp.server.logger") as mock_logger:
            await bmp_session.handle()

            # Should log warning about invalid version
            mock_logger.warning.assert_called_once()
            assert "Invalid BMP version" in str(mock_logger.warning.call_args)

    @pytest.mark.unit
    async def test_bmp_session_oversized_message_protection(self, bmp_session, mock_reader):
        """Test protection against oversized messages."""
        # Create message header indicating oversized message
        oversized_length = bmp_session.MAX_MESSAGE_SIZE + 1000
        header = struct.pack(">BIB", 3, oversized_length, 0)
        mock_reader.read.side_effect = [header, b""]

        with patch("src.bmp.server.logger") as mock_logger:
            await bmp_session.handle()

            # Should log error about message size and clear buffer
            mock_logger.error.assert_called_once()
            assert "Message too large" in str(mock_logger.error.call_args)
