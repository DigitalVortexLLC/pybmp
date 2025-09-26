"""Unit tests for route processor."""
import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.bmp.parser import AFI, SAFI
from src.bmp.processor import RouteProcessor


class TestRouteProcessor:
    """Test route processor functionality."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_processor_initialization(self, mock_db_pool):
        """Test processor initialization."""
        processor = RouteProcessor(mock_db_pool)

        assert processor.db_pool == mock_db_pool
        assert processor.route_buffer == []
        assert isinstance(processor.stats, dict)
        assert processor.stats["messages_processed"] == 0

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_route_monitoring_message(
        self, route_processor, sample_route_monitoring_message
    ):
        """Test processing route monitoring message."""
        router_ip = "192.0.2.100"

        await route_processor.process_message(sample_route_monitoring_message, router_ip)

        # Check that message was processed
        assert route_processor.stats["messages_processed"] == 1
        assert route_processor.stats["routes_processed"] >= 2  # 2 NLRI prefixes

        # Check that routes were buffered
        assert len(route_processor.route_buffer) >= 2

        # Verify route data structure
        route = route_processor.route_buffer[0]
        assert route["router_ip"] == router_ip
        assert route["peer_ip"] == "192.0.2.1"
        assert route["peer_as"] == 65001
        assert route["prefix"] in ["10.0.1.0/24", "10.0.2.0/24"]

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_peer_up_message(self, route_processor, sample_peer_up_message):
        """Test processing peer up message."""
        router_ip = "192.0.2.100"

        await route_processor.process_message(sample_peer_up_message, router_ip)

        # Check that message was processed
        assert route_processor.stats["messages_processed"] == 1

        # Verify database call was made
        route_processor.db_pool.create_or_update_session.assert_called_once()
        call_args = route_processor.db_pool.create_or_update_session.call_args[0][0]
        assert call_args["router_ip"] == router_ip
        assert call_args["status"] == "active"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_peer_down_message(self, route_processor, sample_peer_down_message):
        """Test processing peer down message."""
        router_ip = "192.0.2.100"

        await route_processor.process_message(sample_peer_down_message, router_ip)

        # Check that message was processed
        assert route_processor.stats["messages_processed"] == 1

        # Check that withdrawal route was added
        assert len(route_processor.route_buffer) == 1
        route = route_processor.route_buffer[0]
        assert route["is_withdrawn"] is True

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_stats_message(self, route_processor, sample_stats_message):
        """Test processing statistics message."""
        router_ip = "192.0.2.100"

        await route_processor.process_message(sample_stats_message, router_ip)

        # Check that message was processed
        assert route_processor.stats["messages_processed"] == 1

        # Verify database call was made
        route_processor.db_pool.update_statistics.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_initiation_message(self, route_processor, sample_initiation_message):
        """Test processing initiation message."""
        router_ip = "192.0.2.100"

        await route_processor.process_message(sample_initiation_message, router_ip)

        # Check that message was processed
        assert route_processor.stats["messages_processed"] == 1

        # Verify session creation was called
        route_processor.db_pool.create_or_update_session.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_termination_message(self, route_processor, sample_termination_message):
        """Test processing termination message."""
        router_ip = "192.0.2.100"

        # Mock active sessions
        route_processor.db_pool.get_active_sessions.return_value = [
            {"router_ip": router_ip, "id": 123}
        ]

        await route_processor.process_message(sample_termination_message, router_ip)

        # Check that message was processed
        assert route_processor.stats["messages_processed"] == 1

        # Verify session closure was called
        route_processor.db_pool.close_session.assert_called_once_with(router_ip, 123)

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_create_base_route(self, route_processor, sample_timestamp):
        """Test creating base route structure."""
        router_ip = "192.0.2.100"
        peer_ip = "192.0.2.1"
        peer_as = 65001
        prefix = "10.0.1.0/24"

        route = route_processor._create_base_route(
            router_ip, peer_ip, peer_as, prefix, sample_timestamp
        )

        assert route["router_ip"] == router_ip
        assert route["peer_ip"] == peer_ip
        assert route["peer_as"] == peer_as
        assert route["prefix"] == prefix
        assert route["prefix_len"] == 24
        assert route["time"] == sample_timestamp
        assert route["is_withdrawn"] is False
        assert route["family"] == "IPv4"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_create_route_from_nlri(self, route_processor, sample_timestamp):
        """Test creating route from NLRI with attributes."""
        router_ip = "192.0.2.100"
        peer_ip = "192.0.2.1"
        peer_as = 65001
        prefix = "10.0.1.0/24"
        attributes = {
            "next_hop": "192.0.2.2",
            "origin": 0,
            "as_path": [{"type": "AS_SEQUENCE", "as_numbers": [65001, 65002]}],
            "communities": ["65001:100"],
            "med": 50,
            "local_pref": 100,
        }

        route = route_processor._create_route_from_nlri(
            router_ip, peer_ip, peer_as, prefix, attributes, sample_timestamp, AFI.IPV4
        )

        assert route["next_hop"] == "192.0.2.2"
        assert route["origin"] == 0
        assert route["med"] == 50
        assert route["local_pref"] == 100
        assert json.loads(route["as_path"]) == attributes["as_path"]
        assert json.loads(route["communities"]) == attributes["communities"]

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_create_evpn_route(self, route_processor, sample_timestamp):
        """Test creating EVPN route."""
        router_ip = "192.0.2.100"
        peer_ip = "192.0.2.1"
        peer_as = 65001
        evpn_data = {
            "type": 2,
            "name": "MAC/IP Advertisement",
            "rd": "65001:100",
            "esi": "01234567890123456789",
            "eth_tag": 100,
            "mac": "00:11:22:33:44:55",
        }
        attributes = {"origin": 0, "as_path": [{"type": "AS_SEQUENCE", "as_numbers": [65001]}]}

        route = route_processor._create_evpn_route(
            router_ip, peer_ip, peer_as, evpn_data, attributes, sample_timestamp
        )

        assert route["family"] == "EVPN"
        assert route["afi"] == AFI.L2VPN
        assert route["safi"] == SAFI.EVPN
        assert route["route_type"] == "MAC/IP Advertisement"
        assert route["route_distinguisher"] == "65001:100"
        assert route["mac_address"] == "00:11:22:33:44:55"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_parse_attributes(self, route_processor):
        """Test parsing BGP attributes."""
        attributes = [
            {"type": 1, "value": 0},  # ORIGIN
            {"type": 2, "value": [{"type": "AS_SEQUENCE", "as_numbers": [65001]}]},  # AS_PATH
            {"type": 3, "value": "192.0.2.1"},  # NEXT_HOP
            {"type": 4, "value": 50},  # MED
            {"type": 5, "value": 100},  # LOCAL_PREF
            {"type": 8, "value": ["65001:100"]},  # COMMUNITIES
        ]

        parsed = route_processor._parse_attributes(attributes)

        assert parsed["origin"] == 0
        assert parsed["as_path"] == [{"type": "AS_SEQUENCE", "as_numbers": [65001]}]
        assert parsed["next_hop"] == "192.0.2.1"
        assert parsed["med"] == 50
        assert parsed["local_pref"] == 100
        assert parsed["communities"] == ["65001:100"]

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_get_family(self, route_processor):
        """Test address family determination."""
        assert route_processor._get_family(AFI.IPV4, SAFI.UNICAST) == "IPv4"
        assert route_processor._get_family(AFI.IPV6, SAFI.UNICAST) == "IPv6"
        assert route_processor._get_family(AFI.L2VPN, SAFI.EVPN) == "EVPN"
        assert route_processor._get_family(AFI.IPV4, SAFI.EVPN) == "EVPN"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_get_timestamp(self, route_processor):
        """Test timestamp extraction from peer info."""
        peer_info = {"timestamp_sec": 1704110400, "timestamp_usec": 500000}

        timestamp = route_processor._get_timestamp(peer_info)

        assert isinstance(timestamp, datetime)
        assert timestamp.timestamp() == 1704110400.5

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_get_timestamp_no_timestamp(self, route_processor):
        """Test timestamp when peer info has no timestamp."""
        peer_info = {}

        with patch("src.bmp.processor.datetime") as mock_datetime:
            mock_now = datetime(2024, 1, 1, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            timestamp = route_processor._get_timestamp(peer_info)

            assert timestamp == mock_now

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_flush_routes(self, route_processor, mock_route_batch):
        """Test flushing routes to database."""
        # Add routes to buffer
        route_processor.route_buffer = mock_route_batch.copy()

        await route_processor.flush_routes()

        # Verify database calls were made
        route_processor.db_pool.batch_insert_routes.assert_called_once()

        # Verify routes were processed for history
        assert route_processor.db_pool.update_route_history.call_count == len(mock_route_batch)

        # Buffer should be empty
        assert len(route_processor.route_buffer) == 0

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_flush_routes_empty_buffer(self, route_processor):
        """Test flushing empty route buffer."""
        await route_processor.flush_routes()

        # No database calls should be made
        route_processor.db_pool.batch_insert_routes.assert_not_called()
        route_processor.db_pool.update_route_history.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_flush_routes_database_error(self, route_processor, mock_route_batch):
        """Test handling database error during flush."""
        # Add routes to buffer
        route_processor.route_buffer = mock_route_batch.copy()

        # Mock database error
        route_processor.db_pool.batch_insert_routes.side_effect = Exception("Database error")

        with patch("src.bmp.processor.logger") as mock_logger:
            await route_processor.flush_routes()

            # Error should be logged
            mock_logger.error.assert_called()

            # Routes should be back in buffer
            assert len(route_processor.route_buffer) == len(mock_route_batch)

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_buffer_auto_flush(self, route_processor):
        """Test automatic buffer flush when size limit reached."""
        router_ip = "192.0.2.100"

        # Create message that will generate routes
        message = {
            "type": "route_monitoring",
            "peer": {
                "peer_ip": "192.0.2.1",
                "peer_as": 65001,
                "timestamp_sec": 1704110400,
                "timestamp_usec": 0,
            },
            "bgp_message": {
                "type": "UPDATE",
                "nlri": [f"10.0.{i}.0/24" for i in range(101)],  # 101 routes > 100 buffer limit
            },
        }

        with patch.object(route_processor, "flush_routes") as mock_flush:
            await route_processor.process_message(message, router_ip)

            # Flush should have been called automatically
            mock_flush.assert_called()

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_mp_reach_ipv6(self, route_processor):
        """Test processing MP_REACH_NLRI for IPv6."""
        router_ip = "192.0.2.100"
        peer_ip = "192.0.2.1"
        peer_as = 65001
        timestamp = datetime.utcnow()
        routes = []

        mp_reach = {
            "afi": AFI.IPV6,
            "safi": SAFI.UNICAST,
            "next_hop": "2001:db8::1",
            "nlri": ["2001:db8:1::/64", "2001:db8:2::/64"],
        }

        await route_processor._process_mp_reach(
            mp_reach, router_ip, peer_ip, peer_as, {}, timestamp, routes
        )

        assert len(routes) == 2
        assert routes[0]["family"] == "IPv6"
        assert routes[0]["next_hop"] == "2001:db8::1"
        assert route_processor.stats["routes_processed"] == 2

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_mp_reach_evpn(self, route_processor):
        """Test processing MP_REACH_NLRI for EVPN."""
        router_ip = "192.0.2.100"
        peer_ip = "192.0.2.1"
        peer_as = 65001
        timestamp = datetime.utcnow()
        routes = []

        mp_reach = {
            "afi": AFI.L2VPN,
            "safi": SAFI.EVPN,
            "next_hop": "192.0.2.2",
            "nlri": [{"type": 2, "name": "MAC/IP Advertisement", "mac": "00:11:22:33:44:55"}],
        }

        await route_processor._process_mp_reach(
            mp_reach, router_ip, peer_ip, peer_as, {}, timestamp, routes
        )

        assert len(routes) == 1
        assert routes[0]["family"] == "EVPN"
        assert routes[0]["next_hop"] == "192.0.2.2"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_mp_reach_evpn_type_4(self, route_processor):
        """Test processing MP_REACH_NLRI for EVPN Route Type 4 (Ethernet Segment)."""
        router_ip = "192.0.2.100"
        peer_ip = "192.0.2.1"
        peer_as = 65001
        timestamp = datetime.now(timezone.utc)
        attributes = {"origin": 0, "as_path": [{"type": "AS_SEQUENCE", "as_numbers": [65001]}]}

        # EVPN Route Type 4 data
        mp_reach = {
            "afi": AFI.L2VPN,
            "safi": SAFI.EVPN,
            "next_hop": "192.0.2.2",
            "nlri": [
                {
                    "type": 4,
                    "name": "Ethernet Segment",
                    "rd": "65001:100",
                    "esi": "0123456789abcdef0102",
                    "originating_ip": "192.0.2.1",
                    "ip_length": 32,
                }
            ],
        }

        routes = []
        await route_processor._process_mp_reach(
            mp_reach, router_ip, peer_ip, peer_as, attributes, timestamp, routes
        )

        assert len(routes) == 1
        route = routes[0]
        assert route["family"] == "EVPN"
        assert route["next_hop"] == "192.0.2.2"
        assert route["route_type"] == "Ethernet Segment"
        assert route["route_distinguisher"] == "65001:100"
        assert route["esi"] == "0123456789abcdef0102"
        # Check prefix format for Type 4
        assert route["prefix"] == "evpn:4"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_mp_unreach(self, route_processor):
        """Test processing MP_UNREACH_NLRI."""
        router_ip = "192.0.2.100"
        peer_ip = "192.0.2.1"
        peer_as = 65001
        timestamp = datetime.utcnow()
        routes = []

        mp_unreach = {
            "afi": AFI.IPV4,
            "safi": SAFI.UNICAST,
            "withdrawn": ["10.0.1.0/24", "10.0.2.0/24"],
        }

        await route_processor._process_mp_unreach(
            mp_unreach, router_ip, peer_ip, peer_as, timestamp, routes
        )

        assert len(routes) == 2
        assert all(route["is_withdrawn"] for route in routes)
        assert route_processor.stats["withdrawals_processed"] == 2

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_error_handling(self, route_processor):
        """Test error handling in message processing."""
        router_ip = "192.0.2.100"

        # Create message that triggers error during processing
        # Patch the route processor method to raise an exception
        with patch.object(
            route_processor, "_process_route_monitoring", side_effect=Exception("Test error")
        ):
            valid_message = {"type": "route_monitoring"}

            with patch("src.bmp.processor.logger") as mock_logger:
                await route_processor.process_message(valid_message, router_ip)

        # Error should be counted
        assert route_processor.stats["errors"] == 1

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_invalid_prefix_handling(self, route_processor, sample_timestamp):
        """Test handling of invalid prefix formats."""
        router_ip = "192.0.2.100"
        peer_ip = "192.0.2.1"
        peer_as = 65001

        # Test with invalid prefix
        with patch("src.bmp.processor.logger") as mock_logger:
            route = route_processor._create_base_route(
                router_ip, peer_ip, peer_as, "invalid-prefix", sample_timestamp
            )

            # Should log warning and set prefix_len to 0
            mock_logger.warning.assert_called()
            assert route["prefix_len"] == 0

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_get_stats(self, route_processor):
        """Test getting processing statistics."""
        # Simulate some processing
        route_processor.stats["messages_processed"] = 100
        route_processor.stats["routes_processed"] = 500
        route_processor.stats["withdrawals_processed"] = 50
        route_processor.stats["errors"] = 5

        stats = route_processor.get_stats()

        assert stats["messages_processed"] == 100
        assert stats["routes_processed"] == 500
        assert stats["withdrawals_processed"] == 50
        assert stats["errors"] == 5

        # Ensure it's a copy, not the original
        stats["messages_processed"] = 999
        assert route_processor.stats["messages_processed"] == 100

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_concurrent_buffer_access(self, route_processor):
        """Test concurrent access to route buffer."""
        router_ip = "192.0.2.100"

        # Create multiple concurrent message processing tasks
        message = {
            "type": "route_monitoring",
            "peer": {
                "peer_ip": "192.0.2.1",
                "peer_as": 65001,
                "timestamp_sec": 1704110400,
                "timestamp_usec": 0,
            },
            "bgp_message": {"type": "UPDATE", "nlri": ["10.0.1.0/24"]},
        }

        tasks = []
        for i in range(10):
            task = asyncio.create_task(route_processor.process_message(message, router_ip))
            tasks.append(task)

        await asyncio.gather(*tasks)

        # All messages should be processed without race conditions
        assert route_processor.stats["messages_processed"] == 10
        assert len(route_processor.route_buffer) == 10

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_non_update_bgp_message(self, route_processor):
        """Test processing route monitoring with non-UPDATE BGP message (line 58)."""
        router_ip = "192.0.2.100"
        message = {
            "type": "route_monitoring",
            "peer": {
                "peer_ip": "192.0.2.1",
                "peer_as": 65001,
                "timestamp_sec": 1704110400,
                "timestamp_usec": 0,
            },
            "bgp_message": {"type": "KEEPALIVE"},  # Non-UPDATE message
        }

        await route_processor.process_message(message, router_ip)

        # Should process message but not add any routes
        assert route_processor.stats["messages_processed"] == 1
        assert len(route_processor.route_buffer) == 0

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_invalid_as_number(self, route_processor):
        """Test processing with invalid AS number (lines 67-68)."""
        router_ip = "192.0.2.100"
        message = {
            "type": "route_monitoring",
            "peer": {
                "peer_ip": "192.0.2.1",
                "peer_as": "invalid_as",  # Invalid AS number
                "timestamp_sec": 1704110400,
                "timestamp_usec": 0,
            },
            "bgp_message": {"type": "UPDATE", "nlri": ["10.0.1.0/24"]},
        }

        with patch("src.bmp.processor.logger") as mock_logger:
            await route_processor.process_message(message, router_ip)

        # Should log warning and skip processing
        mock_logger.warning.assert_called_once()
        assert "Invalid AS number" in str(mock_logger.warning.call_args)
        assert len(route_processor.route_buffer) == 0

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_withdrawn_routes(self, route_processor):
        """Test processing withdrawn routes (lines 76-80)."""
        router_ip = "192.0.2.100"
        message = {
            "type": "route_monitoring",
            "peer": {
                "peer_ip": "192.0.2.1",
                "peer_as": 65001,
                "timestamp_sec": 1704110400,
                "timestamp_usec": 0,
            },
            "bgp_message": {"type": "UPDATE", "withdrawn": ["10.0.1.0/24", "10.0.2.0/24"]},
        }

        await route_processor.process_message(message, router_ip)

        # Should process withdrawals
        assert route_processor.stats["messages_processed"] == 1
        assert route_processor.stats["withdrawals_processed"] == 2
        assert len(route_processor.route_buffer) == 2
        assert all(route["is_withdrawn"] for route in route_processor.route_buffer)

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_aggregator_attribute(self, route_processor):
        """Test processing aggregator attribute (lines 273-274)."""
        router_ip = "192.0.2.100"
        message = {
            "type": "route_monitoring",
            "peer": {
                "peer_ip": "192.0.2.1",
                "peer_as": 65001,
                "timestamp_sec": 1704110400,
                "timestamp_usec": 0,
            },
            "bgp_message": {
                "type": "UPDATE",
                "nlri": ["10.0.1.0/24"],
                "attributes": [
                    {"type": 7, "value": {"as": 65002, "ip": "192.0.2.10"}}  # AGGREGATOR
                ],
            },
        }

        await route_processor.process_message(message, router_ip)

        # Should process aggregator
        assert len(route_processor.route_buffer) == 1
        route = route_processor.route_buffer[0]
        assert route["aggregator_as"] == 65002
        assert route["aggregator_ip"] == "192.0.2.10"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_parse_atomic_aggregate_attribute(self, route_processor):
        """Test parsing atomic aggregate attribute (line 353)."""
        attributes = [
            {"type": 6, "value": True},  # ATOMIC_AGGREGATE
        ]

        parsed = route_processor._parse_attributes(attributes)
        assert parsed["atomic_aggregate"] is True

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_parse_originator_id_attribute(self, route_processor):
        """Test parsing originator ID attribute (line 359)."""
        attributes = [
            {"type": 9, "value": "192.0.2.100"},  # ORIGINATOR_ID
        ]

        parsed = route_processor._parse_attributes(attributes)
        assert parsed["originator_id"] == "192.0.2.100"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_parse_cluster_list_attribute(self, route_processor):
        """Test parsing cluster list attribute (line 361)."""
        attributes = [
            {"type": 10, "value": ["192.0.2.1", "192.0.2.2"]},  # CLUSTER_LIST
        ]

        parsed = route_processor._parse_attributes(attributes)
        assert parsed["cluster_list"] == ["192.0.2.1", "192.0.2.2"]

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_parse_extended_communities_attribute(self, route_processor):
        """Test parsing extended communities attribute (line 367)."""
        attributes = [
            {"type": 16, "value": ["RT:65001:100"]},  # EXTENDED_COMMUNITIES
        ]

        parsed = route_processor._parse_attributes(attributes)
        assert parsed["extended_communities"] == ["RT:65001:100"]

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_parse_large_communities_attribute(self, route_processor):
        """Test parsing large communities attribute (line 369)."""
        attributes = [
            {"type": 32, "value": ["65001:100:200"]},  # LARGE_COMMUNITIES
        ]

        parsed = route_processor._parse_attributes(attributes)
        assert parsed["large_communities"] == ["65001:100:200"]

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_stats_duplicate_prefixes(self, route_processor):
        """Test stats processing for duplicate prefixes (line 446)."""
        router_ip = "192.0.2.100"
        message = {
            "type": "stats_report",
            "peer": {
                "peer_ip": "192.0.2.1",
                "peer_as": 65001,
                "timestamp_sec": 1704110400,
                "timestamp_usec": 0,
            },
            "stats": [
                {"type": 1, "value": 50},  # Duplicate prefix count
            ],
        }

        await route_processor.process_message(message, router_ip)

        # Should call update_statistics with duplicate_prefixes
        route_processor.db_pool.update_statistics.assert_called_once()
        call_args = route_processor.db_pool.update_statistics.call_args[0][0]
        assert call_args["duplicate_prefixes"] == 50

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_process_evpn_withdrawal(self, route_processor):
        """Test processing EVPN withdrawal routes (lines 173-175)."""
        router_ip = "192.0.2.100"
        peer_ip = "192.0.2.1"
        peer_as = 65001
        timestamp = datetime.now(timezone.utc)
        routes = []

        mp_unreach = {
            "afi": AFI.L2VPN,
            "safi": SAFI.EVPN,
            "withdrawn": [{"type": 2, "name": "MAC/IP Advertisement", "mac": "00:11:22:33:44:55"}],
        }

        await route_processor._process_mp_unreach(
            mp_unreach, router_ip, peer_ip, peer_as, timestamp, routes
        )

        assert len(routes) == 1
        route = routes[0]
        assert route["is_withdrawn"] is True
        assert route["family"] == "EVPN"
        assert route["mac_address"] == "00:11:22:33:44:55"
