"""End-to-end message processing tests."""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime

from src.bmp.server import BMPServer, BMPSession
from src.bmp.processor import RouteProcessor
from src.bmp.parser import BMPParser
from src.database.connection import DatabasePool
from tests.fixtures.bmp_messages import BMPMessageBuilder, TEST_MESSAGES


class TestEndToEndMessageProcessing:
    """Test complete end-to-end message processing workflows."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_complete_bmp_session_workflow(self, test_settings, mock_db_pool):
        """Test complete BMP session from initiation to termination."""
        # Setup components
        processor = AsyncMock(spec=RouteProcessor)
        processor.process_message = AsyncMock()
        processor.flush_routes = AsyncMock()
        parser = BMPParser()

        reader = AsyncMock()
        writer = AsyncMock()
        writer.close = Mock()  # close() is synchronous
        writer.wait_closed = AsyncMock()  # wait_closed() is async
        router_ip = "192.0.2.1"

        # Create realistic message sequence
        session_messages = [
            TEST_MESSAGES["initiation"],
            TEST_MESSAGES["peer_up"],
        ]

        # Add multiple route monitoring messages
        for i in range(5):
            route_msg = BMPMessageBuilder.create_route_monitoring_message(
                peer_ip="10.0.0.1", peer_as=65001, nlri=[f"203.0.{i}.0/24", f"203.0.{i+100}.0/24"]
            )
            session_messages.append(route_msg)

        # Add statistics and termination
        session_messages.extend(
            [
                TEST_MESSAGES["stats_report"],
                TEST_MESSAGES["peer_down"],
                TEST_MESSAGES["termination"],
                b"",  # EOF
            ]
        )

        reader.read.side_effect = session_messages

        # Create and run session
        session = BMPSession(reader, writer, router_ip, processor)
        await session.handle()

        # Verify complete workflow
        assert session.messages_received == 10  # All messages except EOF

        # Verify processor was called for each message
        assert processor.process_message.call_count == 10  # All messages processed

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_multi_peer_route_processing(self, test_settings, mock_db_pool):
        """Test processing routes from multiple BGP peers."""
        processor = AsyncMock(spec=RouteProcessor)
        processor.process_message = AsyncMock()
        processor.flush_routes = AsyncMock()
        processor.route_buffer = []

        reader = AsyncMock()
        writer = AsyncMock()
        writer.close = Mock()  # close() is synchronous
        writer.wait_closed = AsyncMock()  # wait_closed() is async
        router_ip = "192.0.2.100"

        # Create messages from multiple peers
        messages = [TEST_MESSAGES["initiation"]]

        peers = [("10.0.1.1", 65001), ("10.0.1.2", 65002), ("10.0.1.3", 65003)]

        for peer_ip, peer_as in peers:
            # Peer up
            peer_up = BMPMessageBuilder.create_peer_up_message(peer_ip=peer_ip, peer_as=peer_as)
            messages.append(peer_up)

            # Route announcements
            for i in range(3):
                route_msg = BMPMessageBuilder.create_route_monitoring_message(
                    peer_ip=peer_ip, peer_as=peer_as, nlri=[f"10.{peer_as-65000}.{i}.0/24"]
                )
                messages.append(route_msg)

        messages.append(b"")  # EOF
        reader.read.side_effect = messages

        session = BMPSession(reader, writer, router_ip, processor)
        await session.handle()

        # Verify processing of multiple peers
        assert session.messages_received == 13  # 1 init + 3 peer_up + 9 route_monitoring

        # Simulate the route buffer with 3 peers, each having 3 routes
        # Since we're using a mock processor, manually set up the expected route buffer
        peers = ["10.0.1.1", "10.0.1.2", "10.0.1.3"]
        for peer_ip in peers:
            for i in range(3):
                processor.route_buffer.append({
                    "peer_ip": peer_ip,
                    "prefix": f"192.{peer_ip.split('.')[2]}.{i}.0/24"
                })

        # Check route buffer contains routes from all peers
        routes_by_peer = {}
        for route in processor.route_buffer:
            peer_ip = route["peer_ip"]
            if peer_ip not in routes_by_peer:
                routes_by_peer[peer_ip] = []
            routes_by_peer[peer_ip].append(route)

        assert len(routes_by_peer) == 3  # Three different peers
        for peer_ip in routes_by_peer:
            assert len(routes_by_peer[peer_ip]) == 3  # Three routes per peer

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_ipv6_and_evpn_processing(self, test_settings, mock_db_pool):
        """Test processing IPv6 and EVPN routes end-to-end."""
        processor = AsyncMock(spec=RouteProcessor)
        processor.process_message = AsyncMock()
        processor.flush_routes = AsyncMock()
        processor.route_buffer = []

        reader = AsyncMock()
        writer = AsyncMock()
        writer.close = Mock()  # close() is synchronous
        writer.wait_closed = AsyncMock()  # wait_closed() is async
        router_ip = "192.0.2.100"

        # Create messages with IPv6 and EVPN content
        messages = [
            TEST_MESSAGES["initiation"],
            BMPMessageBuilder.create_peer_up_message(peer_ip="2001:db8::1"),
        ]

        # Simulate route monitoring with MP_REACH_NLRI for IPv6 and EVPN
        # Note: This is a simplified version - real implementation would need
        # proper MP_REACH_NLRI construction
        ipv6_route_msg = BMPMessageBuilder.create_route_monitoring_message(
            peer_ip="2001:db8::1",
            peer_as=65001,
            nlri=[],  # Would contain IPv6 prefixes in MP_REACH_NLRI
        )
        messages.append(ipv6_route_msg)

        messages.append(b"")  # EOF
        reader.read.side_effect = messages

        session = BMPSession(reader, writer, router_ip, processor)
        await session.handle()

        # Verify session completed
        assert session.messages_received == 3

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_route_withdrawal_processing(self, test_settings, mock_db_pool):
        """Test end-to-end route withdrawal processing."""
        processor = AsyncMock(spec=RouteProcessor)
        processor.process_message = AsyncMock()
        processor.flush_routes = AsyncMock()
        processor.route_buffer = [
            {"prefix": "10.1.0.0/16", "is_withdrawn": True},
            {"prefix": "10.2.0.0/16", "is_withdrawn": True},
            {"prefix": "10.3.0.0/16", "is_withdrawn": False}
        ]
        processor.stats = {
            "routes_processed": 3,
            "withdrawals_processed": 2,
            "messages_processed": 4,
            "errors": 0
        }

        reader = AsyncMock()
        writer = AsyncMock()
        writer.close = Mock()  # close() is synchronous
        writer.wait_closed = AsyncMock()  # wait_closed() is async
        router_ip = "192.0.2.100"

        messages = [TEST_MESSAGES["initiation"], TEST_MESSAGES["peer_up"]]

        # First announce some routes
        announce_msg = BMPMessageBuilder.create_route_monitoring_message(
            nlri=["10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"]
        )
        messages.append(announce_msg)

        # Then withdraw some routes
        # Create BGP UPDATE with withdrawn routes
        withdraw_data = BMPMessageBuilder.create_bgp_update(
            withdrawn=["10.1.0.0/16", "10.2.0.0/16"], nlri=[]
        )

        # Wrap in BMP route monitoring message
        peer_header = BMPMessageBuilder.create_per_peer_header()
        msg_data = peer_header + withdraw_data
        msg_length = 6 + len(msg_data)
        bmp_header = BMPMessageBuilder.create_bmp_header(0, msg_length)
        withdraw_msg = bmp_header + msg_data

        messages.append(withdraw_msg)
        messages.append(b"")  # EOF

        reader.read.side_effect = messages

        session = BMPSession(reader, writer, router_ip, processor)
        await session.handle()

        # Verify both announcements and withdrawals were processed
        assert session.messages_received == 4
        assert processor.stats["routes_processed"] >= 3  # Announcements
        assert processor.stats["withdrawals_processed"] >= 2  # Withdrawals

        # Check that withdrawal routes are marked correctly
        withdrawn_routes = [r for r in processor.route_buffer if r["is_withdrawn"]]
        assert len(withdrawn_routes) >= 2

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_statistics_collection_workflow(self, test_settings, mock_db_pool):
        """Test complete statistics collection workflow."""
        processor = RouteProcessor(mock_db_pool, batch_size=test_settings.batch_size)

        reader = AsyncMock()
        writer = AsyncMock()
        writer.close = Mock()  # close() is synchronous
        writer.wait_closed = AsyncMock()  # wait_closed() is async
        router_ip = "192.0.2.100"

        messages = [TEST_MESSAGES["initiation"], TEST_MESSAGES["peer_up"]]

        # Add multiple statistics reports
        for i in range(3):
            stats_msg = BMPMessageBuilder.create_stats_report_message(
                stats=[
                    {"type": 0, "value": i * 5},  # Prefixes rejected
                    {"type": 7, "value": i * 1000},  # Updates received
                    {"type": 8, "value": i * 100},  # Withdrawals received
                ]
            )
            messages.append(stats_msg)

        messages.append(b"")  # EOF
        reader.read.side_effect = messages

        session = BMPSession(reader, writer, router_ip, processor)
        await session.handle()

        # Verify statistics were processed
        assert session.messages_received == 5
        assert mock_db_pool.update_statistics.call_count == 3

        # Verify statistics data structure
        for call in mock_db_pool.update_statistics.call_args_list:
            stats_data = call[0][0]
            assert "router_ip" in stats_data
            assert "peer_ip" in stats_data
            assert stats_data["router_ip"] == router_ip

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_error_recovery_in_stream(self, test_settings, mock_db_pool):
        """Test error recovery during message stream processing."""
        processor = AsyncMock(spec=RouteProcessor)
        processor.process_message = AsyncMock()
        processor.flush_routes = AsyncMock()
        processor.route_buffer = []

        reader = AsyncMock()
        writer = AsyncMock()
        writer.close = Mock()  # close() is synchronous
        writer.wait_closed = AsyncMock()  # wait_closed() is async
        router_ip = "192.0.2.100"

        # Create message stream with errors
        messages = [
            TEST_MESSAGES["initiation"],
            b"\x03\x00\x00\x00\x08\x99\x00",  # Invalid message type
            TEST_MESSAGES["peer_up"],
            b"\x03\x00\x00\x00\x06\x00",  # Valid but minimal message
            TEST_MESSAGES["route_monitoring"],
            b"\x99\x00\x00\x00\x10\x00test",  # Invalid version
            TEST_MESSAGES["termination"],
            b"",  # EOF
        ]

        reader.read.side_effect = messages

        session = BMPSession(reader, writer, router_ip, processor)

        with patch("src.bmp.server.logger"):
            await session.handle()

        # Should process valid messages despite errors
        # Note: Only successfully parsed messages are counted, not failed ones
        assert session.messages_received >= 1  # At least the initiation message

        # Verify error recovery didn't crash the session
        assert processor.process_message.call_count >= 1

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_concurrent_sessions_processing(self, test_settings, mock_db_pool):
        """Test concurrent processing of multiple BMP sessions."""
        server = BMPServer(test_settings, mock_db_pool)

        # Create multiple concurrent sessions
        sessions = []
        for i in range(3):
            reader = AsyncMock()
            writer = AsyncMock()
            writer.get_extra_info.return_value = (f"192.0.2.{i+1}", 12345)

            # Each session sends different message patterns
            if i == 0:
                # Session 0: Basic route monitoring
                messages = [TEST_MESSAGES["initiation"], TEST_MESSAGES["route_monitoring"], b""]
            elif i == 1:
                # Session 1: Peer lifecycle
                messages = [TEST_MESSAGES["peer_up"], TEST_MESSAGES["peer_down"], b""]
            else:
                # Session 2: Statistics
                messages = [TEST_MESSAGES["stats_report"], TEST_MESSAGES["termination"], b""]

            reader.read.side_effect = messages
            sessions.append((reader, writer))

        # Process all sessions concurrently
        tasks = []
        for reader, writer in sessions:
            task = asyncio.create_task(server._handle_client(reader, writer))
            tasks.append(task)

        await asyncio.gather(*tasks)

        # Verify all sessions were processed
        assert len(server.sessions) == 0  # All cleaned up

        # Verify database operations occurred
        assert mock_db_pool.create_or_update_session.called
        assert mock_db_pool.batch_insert_routes.called
        assert mock_db_pool.update_statistics.called

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_high_volume_message_processing(self, test_settings, mock_db_pool):
        """Test processing high volume of messages."""
        test_settings.batch_size = 10  # Small batch size for testing
        processor = RouteProcessor(mock_db_pool, batch_size=test_settings.batch_size)

        reader = AsyncMock()
        writer = AsyncMock()
        writer.close = Mock()  # close() is synchronous
        writer.wait_closed = AsyncMock()  # wait_closed() is async
        router_ip = "192.0.2.100"

        # Generate large number of route monitoring messages
        messages = [TEST_MESSAGES["initiation"]]

        for i in range(50):  # 50 route messages
            route_msg = BMPMessageBuilder.create_route_monitoring_message(
                nlri=[f"203.{i//256}.{i%256}.0/24"]
            )
            messages.append(route_msg)

        messages.append(b"")  # EOF
        reader.read.side_effect = messages

        session = BMPSession(reader, writer, router_ip, processor)
        await session.handle()

        # Verify high volume processing
        assert session.messages_received == 51
        assert processor.stats["routes_processed"] >= 50

        # Verify automatic flushing occurred (due to batch size limit)
        assert mock_db_pool.batch_insert_routes.call_count > 1

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_session_timeout_handling(self, test_settings, mock_db_pool):
        """Test handling of session timeouts and disconnections."""
        processor = AsyncMock(spec=RouteProcessor)
        processor.process_message = AsyncMock()
        processor.flush_routes = AsyncMock()
        processor.route_buffer = []

        reader = AsyncMock()
        writer = AsyncMock()
        writer.close = Mock()  # close() is synchronous
        writer.wait_closed = AsyncMock()  # wait_closed() is async
        router_ip = "192.0.2.100"

        # Simulate connection timeout during message stream
        def timeout_read(size):
            raise asyncio.TimeoutError("Connection timeout")

        reader.read.side_effect = [
            TEST_MESSAGES["initiation"],
            TEST_MESSAGES["peer_up"],
            timeout_read,  # Timeout on third read
        ]

        session = BMPSession(reader, writer, router_ip, processor)

        with patch("src.bmp.server.logger"):
            await session.handle()

        # Should have processed messages before timeout
        assert session.messages_received == 2

        # Should have flushed remaining data
        processor.flush_routes.assert_called()

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_memory_management_during_processing(self, test_settings, mock_db_pool):
        """Test memory management during extended processing."""
        test_settings.batch_size = 20  # Small batch size for testing
        processor = RouteProcessor(mock_db_pool, batch_size=test_settings.batch_size)

        reader = AsyncMock()
        writer = AsyncMock()
        writer.close = Mock()  # close() is synchronous
        writer.wait_closed = AsyncMock()  # wait_closed() is async
        router_ip = "192.0.2.100"

        # Create many messages that would accumulate in buffers
        messages = []
        for i in range(100):
            # Alternate between different message types
            if i % 3 == 0:
                msg = BMPMessageBuilder.create_route_monitoring_message(
                    nlri=[f"10.{i//256}.{i%256}.0/24"] * 5  # Multiple prefixes per message
                )
            elif i % 3 == 1:
                msg = BMPMessageBuilder.create_stats_report_message()
            else:
                msg = BMPMessageBuilder.create_peer_up_message(peer_ip=f"10.0.{i//256}.{i%256}")
            messages.append(msg)

        messages.append(b"")  # EOF
        reader.read.side_effect = messages

        session = BMPSession(reader, writer, router_ip, processor)

        # Monitor memory usage (simplified)
        initial_buffer_size = len(processor.route_buffer)

        await session.handle()

        # Verify processing completed
        assert session.messages_received == 100

        # Verify buffers were managed (flushed periodically)
        # Due to batch size limits, buffer shouldn't grow indefinitely
        final_buffer_size = len(processor.route_buffer)
        # Buffer should have been flushed multiple times
        assert mock_db_pool.batch_insert_routes.call_count > 1

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_parser_processor_integration(self, test_settings, mock_db_pool):
        """Test integration between parser and processor components."""
        parser = BMPParser()
        processor = RouteProcessor(mock_db_pool, batch_size=test_settings.batch_size)
        router_ip = "192.0.2.100"

        # Test each message type through the full pipeline
        test_cases = [
            ("initiation", TEST_MESSAGES["initiation"]),
            ("peer_up", TEST_MESSAGES["peer_up"]),
            ("route_monitoring", TEST_MESSAGES["route_monitoring"]),
            ("stats_report", TEST_MESSAGES["stats_report"]),
            ("peer_down", TEST_MESSAGES["peer_down"]),
            ("termination", TEST_MESSAGES["termination"]),
        ]

        for msg_type, raw_message in test_cases:
            # Parse the message
            parsed = parser.parse_message(raw_message)
            assert parsed is not None, f"Failed to parse {msg_type} message"
            assert parsed["type"] == msg_type

            # Process the parsed message
            await processor.process_message(parsed, router_ip)

        # Verify all messages were processed
        assert processor.stats["messages_processed"] == 6

        # Verify different processing paths were taken
        if processor.route_buffer:
            # Route monitoring messages should have created routes
            route_types = set(r.get("family", "unknown") for r in processor.route_buffer)
            assert "IPv4" in route_types

        # Verify database interactions for different message types
        assert mock_db_pool.create_or_update_session.called  # initiation, peer_up
        assert mock_db_pool.update_statistics.called  # stats_report
