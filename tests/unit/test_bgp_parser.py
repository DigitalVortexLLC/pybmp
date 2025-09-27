"""Unit tests for BGP message parser - clean version."""
import ipaddress
import struct

import pytest

from src.bmp.bgp_parser import AFI, SAFI, BGPMessageParser


class TestBGPMessageParser:
    """Test BGP message parser functionality."""

    @pytest.fixture
    def bgp_parser(self):
        """Create BGP parser instance."""
        return BGPMessageParser()

    @pytest.mark.unit
    def test_parser_initialization(self, bgp_parser):
        """Test BGP parser initialization."""
        assert bgp_parser is not None
        assert hasattr(bgp_parser, "evpn_parser")

    @pytest.mark.unit
    def test_parse_bgp_message_invalid_length(self, bgp_parser):
        """Test parsing BGP message with invalid length."""
        # Too short for BGP header
        invalid_data = b"short"
        result = bgp_parser.parse_bgp_message(invalid_data)
        assert result is None

    @pytest.mark.unit
    def test_parse_bgp_message_keepalive(self, bgp_parser):
        """Test parsing BGP KEEPALIVE message."""
        # Create valid BGP KEEPALIVE message
        keepalive_data = struct.pack(">16sHBB", b"\xff" * 16, 19, 4, 0)
        result = bgp_parser.parse_bgp_message(keepalive_data)
        assert result is not None
        assert result["type"] == "KEEPALIVE"

    @pytest.mark.unit
    def test_parse_bgp_message_notification(self, bgp_parser):
        """Test parsing BGP NOTIFICATION message."""
        # Create BGP NOTIFICATION message
        notification_payload = struct.pack(">BB", 1, 1)  # Error code 1, subcode 1
        notification_data = struct.pack(">16sHBB", b"\xff" * 16, 21, 3, 0) + notification_payload
        result = bgp_parser.parse_bgp_message(notification_data)
        assert result is not None
        assert result["type"] == "NOTIFICATION"

    @pytest.mark.unit
    def test_parse_bgp_message_unknown_type(self, bgp_parser):
        """Test parsing unknown BGP message type."""
        # Create message with unknown type
        unknown_data = struct.pack(">16sHBB", b"\xff" * 16, 19, 99, 0)  # Type 99
        result = bgp_parser.parse_bgp_message(unknown_data)
        assert result is None

    @pytest.mark.unit
    def test_parse_next_hop_ipv4(self, bgp_parser):
        """Test parsing IPv4 next hop."""
        next_hop_data = struct.pack(">I", 0xC0000201)  # 192.0.2.1
        result = bgp_parser._parse_next_hop(next_hop_data, AFI.IPV4)
        assert result == "192.0.2.1"

    @pytest.mark.unit
    def test_parse_next_hop_ipv6(self, bgp_parser):
        """Test parsing IPv6 next hop."""
        # IPv6 address 2001:db8::1
        ipv6_bytes = ipaddress.IPv6Address("2001:db8::1").packed
        result = bgp_parser._parse_next_hop(ipv6_bytes, AFI.IPV6)
        assert result == "2001:db8::1"

    @pytest.mark.unit
    def test_parse_as_path_sequence(self, bgp_parser):
        """Test parsing AS_PATH with AS_SEQUENCE."""
        # AS_SEQUENCE with 2 AS numbers
        as_path_data = struct.pack(">BBH", 2, 2, 65001) + struct.pack(">H", 65002)
        result = bgp_parser._parse_as_path(as_path_data)
        assert result == [{"type": "AS_SEQUENCE", "as_numbers": [65001, 65002]}]

    @pytest.mark.unit
    def test_parse_as_path_set(self, bgp_parser):
        """Test parsing AS_PATH with AS_SET."""
        # AS_SET with 1 AS number
        as_path_data = struct.pack(">BBH", 1, 1, 65001)
        result = bgp_parser._parse_as_path(as_path_data)
        assert result == [{"type": "AS_SET", "as_numbers": [65001]}]

    @pytest.mark.unit
    def test_parse_communities(self, bgp_parser):
        """Test parsing communities attribute."""
        # Two communities: 65001:100 and 65002:200
        communities_data = struct.pack(">HHHH", 65001, 100, 65002, 200)
        result = bgp_parser._parse_communities(communities_data)
        assert result == ["65001:100", "65002:200"]

    @pytest.mark.unit
    def test_parse_large_communities(self, bgp_parser):
        """Test parsing large communities attribute."""
        # One large community: 65001:100:200
        large_comm_data = struct.pack(">III", 65001, 100, 200)
        result = bgp_parser._parse_large_communities(large_comm_data)
        assert result == ["65001:100:200"]

    @pytest.mark.unit
    def test_get_bgp_message_type_name(self, bgp_parser):
        """Test BGP message type name conversion."""
        assert bgp_parser._get_bgp_message_type_name(1) == "OPEN"
        assert bgp_parser._get_bgp_message_type_name(2) == "UPDATE"
        assert bgp_parser._get_bgp_message_type_name(3) == "NOTIFICATION"
        assert bgp_parser._get_bgp_message_type_name(4) == "KEEPALIVE"
        assert bgp_parser._get_bgp_message_type_name(99) == "UNKNOWN"

    @pytest.mark.unit
    def test_parse_bgp_open_message(self, bgp_parser):
        """Test parsing BGP OPEN message."""
        # Create complete OPEN message
        open_payload = struct.pack(">BHHIB", 4, 65001, 180, 0xC0000201, 0)
        open_data = struct.pack(">16sHB", b"\xff" * 16, 29, 1) + open_payload
        result = bgp_parser.parse_bgp_message(open_data)
        assert result is not None
        assert result["type"] == "OPEN"
        assert result["version"] == 4
        assert result["as_number"] == 65001
        assert result["hold_time"] == 180

    @pytest.mark.unit
    def test_parse_bgp_update_minimal(self, bgp_parser):
        """Test parsing minimal BGP UPDATE message."""
        # UPDATE with no withdrawn routes, no path attributes, no NLRI
        update_payload = struct.pack(">HH", 0, 0)  # withdrawn_len=0, attr_len=0
        update_data = struct.pack(">16sHB", b"\xff" * 16, 23, 2) + update_payload
        result = bgp_parser.parse_bgp_message(update_data)
        assert result is not None
        assert result["type"] == "UPDATE"
        assert result["withdrawn"] == []
        assert result["attributes"] == []
        assert result["nlri"] == []

    @pytest.mark.unit
    def test_parse_bgp_update_with_nlri(self, bgp_parser):
        """Test parsing BGP UPDATE with NLRI."""
        # UPDATE with one NLRI prefix
        withdrawn_len = struct.pack(">H", 0)
        path_attr_len = struct.pack(">H", 0)
        nlri = struct.pack(">B", 24) + struct.pack(">BBB", 10, 0, 1)  # 10.0.1.0/24

        update_payload = withdrawn_len + path_attr_len + nlri
        length = 19 + len(update_payload)
        update_data = struct.pack(">16sHB", b"\xff" * 16, length, 2) + update_payload

        result = bgp_parser.parse_bgp_message(update_data)
        assert result is not None
        assert result["type"] == "UPDATE"
        assert len(result["nlri"]) == 1
        assert "10.0.1.0/24" in result["nlri"]

    @pytest.mark.unit
    def test_parse_mp_reach_nlri_ipv4(self, bgp_parser):
        """Test parsing MP_REACH_NLRI for IPv4."""
        # MP_REACH_NLRI with IPv4 prefix
        mp_reach_data = struct.pack(">HB", AFI.IPV4, SAFI.UNICAST)  # AFI, SAFI
        mp_reach_data += struct.pack(">B", 4)  # Next hop length
        mp_reach_data += struct.pack(">I", 0xC0000201)  # Next hop 192.0.2.1
        mp_reach_data += struct.pack(">B", 0)  # Reserved
        mp_reach_data += struct.pack(">B", 24) + struct.pack(">BBB", 10, 0, 1)  # 10.0.1.0/24

        result = bgp_parser._parse_mp_reach_nlri(mp_reach_data)
        assert result is not None
        assert result["afi"] == AFI.IPV4
        assert result["safi"] == SAFI.UNICAST
        assert result["next_hop"] == "192.0.2.1"
        assert len(result["nlri"]) == 1

    @pytest.mark.unit
    def test_parse_mp_reach_nlri_ipv6(self, bgp_parser):
        """Test parsing MP_REACH_NLRI for IPv6."""
        # MP_REACH_NLRI with IPv6 prefix
        mp_reach_data = struct.pack(">HB", AFI.IPV6, SAFI.UNICAST)  # AFI, SAFI
        mp_reach_data += struct.pack(">B", 16)  # Next hop length
        mp_reach_data += ipaddress.IPv6Address("2001:db8::1").packed  # Next hop
        mp_reach_data += struct.pack(">B", 0)  # Reserved
        mp_reach_data += (
            struct.pack(">B", 64)
            + ipaddress.IPv6Network("2001:db8:1::/64").network_address.packed[:8]
        )

        result = bgp_parser._parse_mp_reach_nlri(mp_reach_data)
        assert result is not None
        assert result["afi"] == AFI.IPV6
        assert result["safi"] == SAFI.UNICAST
        assert result["next_hop"] == "2001:db8::1"

    @pytest.mark.unit
    def test_parse_mp_unreach_nlri(self, bgp_parser):
        """Test parsing MP_UNREACH_NLRI."""
        # MP_UNREACH_NLRI for IPv4
        mp_unreach_data = struct.pack(">HB", AFI.IPV4, SAFI.UNICAST)  # AFI, SAFI
        mp_unreach_data += struct.pack(">B", 24) + struct.pack(">BBB", 10, 0, 1)  # 10.0.1.0/24

        result = bgp_parser._parse_mp_unreach_nlri(mp_unreach_data)
        assert result is not None
        assert result["afi"] == AFI.IPV4
        assert result["safi"] == SAFI.UNICAST

    @pytest.mark.unit
    def test_parse_ipv6_nlri(self, bgp_parser):
        """Test parsing IPv6 NLRI."""
        # IPv6 prefix 2001:db8::/32
        ipv6_nlri = (
            struct.pack(">B", 32)
            + ipaddress.IPv6Network("2001:db8::/32").network_address.packed[:4]
        )
        result = bgp_parser._parse_ipv6_nlri(ipv6_nlri)
        assert len(result) == 1
        assert "2001:db8::/32" in result

    @pytest.mark.unit
    def test_parse_capabilities(self, bgp_parser):
        """Test parsing capabilities."""
        # Multiprotocol capability for IPv4 unicast
        capability_data = struct.pack(">BBHBB", 1, 4, AFI.IPV4, 0, SAFI.UNICAST)
        result = bgp_parser._parse_capabilities(capability_data)
        assert len(result) == 1
        assert result[0]["type"] == 1


class TestBGPParserAdditional:
    """Test additional BGP parser functionality."""

    @pytest.fixture
    def bgp_parser(self):
        """Create BGP parser instance."""
        return BGPMessageParser()

    @pytest.mark.unit
    def test_parse_bgp_message_empty_data(self, bgp_parser):
        """Test BGP message parsing with empty data."""
        result = bgp_parser.parse_bgp_message(b"")
        assert result is None

    @pytest.mark.unit
    def test_parse_bgp_message_short_data(self, bgp_parser):
        """Test BGP message parsing with insufficient data."""
        short_data = b"x"  # Only 1 byte
        result = bgp_parser.parse_bgp_message(short_data)
        assert result is None

    @pytest.mark.unit
    def test_parse_as_path_empty(self, bgp_parser):
        """Test parsing empty AS_PATH."""
        result = bgp_parser._parse_as_path(b"")
        assert result == []

    @pytest.mark.unit
    def test_parse_communities_invalid_length(self, bgp_parser):
        """Test parsing communities with invalid length."""
        # Only 3 bytes instead of multiple of 4
        invalid_communities = b"\x00\x01\x02"
        result = bgp_parser._parse_communities(invalid_communities)
        assert result == []

    @pytest.mark.unit
    def test_parse_large_communities_invalid_length(self, bgp_parser):
        """Test parsing large communities with invalid length."""
        # Only 11 bytes instead of multiple of 12
        invalid_large_comm = b"\x00" * 11
        result = bgp_parser._parse_large_communities(invalid_large_comm)
        assert result == []

    @pytest.mark.unit
    def test_parse_mp_reach_nlri_insufficient_data(self, bgp_parser):
        """Test MP_REACH_NLRI with insufficient data."""
        # Only AFI, missing SAFI and rest
        insufficient_data = struct.pack(">H", AFI.IPV4)
        result = bgp_parser._parse_mp_reach_nlri(insufficient_data)
        assert result is None

    @pytest.mark.unit
    def test_parse_mp_unreach_nlri_insufficient_data(self, bgp_parser):
        """Test MP_UNREACH_NLRI with insufficient data."""
        # Only AFI, missing SAFI
        insufficient_data = struct.pack(">H", AFI.IPV4)
        result = bgp_parser._parse_mp_unreach_nlri(insufficient_data)
        assert result is None

    @pytest.mark.unit
    def test_parse_next_hop_unknown_afi(self, bgp_parser):
        """Test parsing next hop with unknown AFI."""
        next_hop_data = b"\x01\x02\x03\x04"
        result = bgp_parser._parse_next_hop(next_hop_data, 99)  # Unknown AFI
        assert result == "01020304"  # Returns hex representation

    @pytest.mark.unit
    def test_parse_capabilities_empty(self, bgp_parser):
        """Test parsing empty capabilities."""
        result = bgp_parser._parse_capabilities(b"")
        assert result == []

    @pytest.mark.unit
    def test_parse_capabilities_insufficient_data(self, bgp_parser):
        """Test parsing capabilities with insufficient data."""
        # Only capability type, no length
        insufficient_data = b"\x01"
        result = bgp_parser._parse_capabilities(insufficient_data)
        assert result == []
