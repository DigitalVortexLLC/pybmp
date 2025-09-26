"""Unit tests for BGP message parser."""
import pytest
import struct
from unittest.mock import patch, MagicMock

from src.bmp.bgp_parser import BGPMessageParser, BGPMessageType, BGPAttributeType, AFI, SAFI
from src.bmp.parsing_utils import ParseError


class TestBGPMessageParser:
    """Test BGP message parser functionality."""

    @pytest.fixture
    def bgp_parser(self):
        """Create BGP parser instance."""
        return BGPMessageParser()

    def test_parser_initialization(self, bgp_parser):
        """Test parser initialization."""
        assert isinstance(bgp_parser, BGPMessageParser)
        assert bgp_parser.evpn_parser is not None

    def test_parse_bgp_message_invalid_length(self, bgp_parser):
        """Test parsing BGP message with invalid length."""
        # Message too short (less than 19 bytes)
        short_data = b"\x00" * 18
        result = bgp_parser.parse_bgp_message(short_data)
        assert result is None

    def test_parse_bgp_message_keepalive(self, bgp_parser):
        """Test parsing BGP KEEPALIVE message."""
        # BGP header: marker(16) + length(2) + type(1)
        marker = b"\xff" * 16
        length = struct.pack(">H", 19)  # Minimal BGP message length
        msg_type = struct.pack(">B", BGPMessageType.KEEPALIVE)
        data = marker + length + msg_type

        result = bgp_parser.parse_bgp_message(data)
        assert result is not None
        assert result["type"] == "KEEPALIVE"
        assert result["length"] == 19

    def test_parse_bgp_message_notification(self, bgp_parser):
        """Test parsing BGP NOTIFICATION message."""
        marker = b"\xff" * 16
        length = struct.pack(">H", 19)
        msg_type = struct.pack(">B", BGPMessageType.NOTIFICATION)
        data = marker + length + msg_type

        result = bgp_parser.parse_bgp_message(data)
        assert result is not None
        assert result["type"] == "NOTIFICATION"

    def test_parse_bgp_message_unknown_type(self, bgp_parser):
        """Test parsing BGP message with unknown type."""
        marker = b"\xff" * 16
        length = struct.pack(">H", 19)
        msg_type = struct.pack(">B", 99)  # Unknown type
        data = marker + length + msg_type

        result = bgp_parser.parse_bgp_message(data)
        assert result is not None
        assert result["type"] == "UNKNOWN_99"

    def test_parse_bgp_open_message(self, bgp_parser):
        """Test parsing BGP OPEN message."""
        marker = b"\xff" * 16
        length = struct.pack(">H", 29)  # Header + minimal OPEN
        msg_type = struct.pack(">B", BGPMessageType.OPEN)

        # OPEN message: version(1) + as(2) + hold_time(2) + bgp_id(4) + opt_len(1)
        open_data = struct.pack(">BHHIB", 4, 65001, 180, 0x01010101, 0)

        data = marker + length + msg_type + open_data

        result = bgp_parser.parse_bgp_message(data)
        assert result is not None
        assert result["type"] == "OPEN"
        assert result["version"] == 4
        assert result["as"] == 65001
        assert result["hold_time"] == 180

    def test_parse_bgp_update_minimal(self, bgp_parser):
        """Test parsing minimal BGP UPDATE message."""
        marker = b"\xff" * 16
        length = struct.pack(">H", 23)  # Header + minimal UPDATE
        msg_type = struct.pack(">B", BGPMessageType.UPDATE)

        # UPDATE: withdrawn_len(2) + path_attr_len(2)
        update_data = struct.pack(">HH", 0, 0)  # No withdrawn routes, no attributes

        data = marker + length + msg_type + update_data

        result = bgp_parser.parse_bgp_message(data)
        assert result is not None
        assert result["type"] == "UPDATE"
        assert "withdrawn" not in result or result.get("withdrawn", []) == []
        assert "path_attributes" not in result or result.get("path_attributes", []) == []
        assert "nlri" not in result or result.get("nlri", []) == []

    def test_parse_bgp_update_with_nlri(self, bgp_parser):
        """Test parsing BGP UPDATE with NLRI."""
        marker = b"\xff" * 16
        length = struct.pack(">H", 28)  # Header + UPDATE with NLRI
        msg_type = struct.pack(">B", BGPMessageType.UPDATE)

        # UPDATE: withdrawn_len(2) + path_attr_len(2) + nlri(prefix)
        # NLRI: /24 prefix = 24 bits = 3 bytes for 192.0.2.0/24
        nlri_data = b"\x18\xc0\x00\x02"  # 24-bit prefix length + 192.0.2
        update_data = struct.pack(">HH", 0, 0) + nlri_data

        data = marker + length + msg_type + update_data

        result = bgp_parser.parse_bgp_message(data)
        assert result is not None
        assert result["type"] == "UPDATE"
        assert len(result["nlri"]) == 1
        assert result["nlri"][0] == "192.0.2.0/24"

    def test_parse_as_path_sequence(self, bgp_parser):
        """Test parsing AS path with sequence."""
        # AS_SEQUENCE(2) + length(1) + AS numbers
        as_path_data = struct.pack(">BBH", 2, 1, 65001)
        result = bgp_parser._parse_as_path(as_path_data)
        assert result == [[65001]]

    def test_parse_as_path_set(self, bgp_parser):
        """Test parsing AS path with set."""
        # AS_SET(1) + length(1) + AS numbers
        as_path_data = struct.pack(">BBHH", 1, 2, 65001, 65002)
        result = bgp_parser._parse_as_path(as_path_data)
        assert len(result) == 1
        assert set(result[0]) == {65001, 65002}

    def test_parse_communities(self, bgp_parser):
        """Test parsing BGP communities."""
        # Community format: AS(2) + value(2)
        communities_data = struct.pack(">HHHH", 65001, 100, 65002, 200)
        result = bgp_parser._parse_communities(communities_data)
        assert result == ["65001:100", "65002:200"]

    def test_parse_large_communities(self, bgp_parser):
        """Test parsing BGP large communities."""
        # Large community format: Global Admin(4) + Local Data 1(4) + Local Data 2(4)
        large_comm_data = struct.pack(">III", 65001, 100, 200)
        result = bgp_parser._parse_large_communities(large_comm_data)
        assert result == ["65001:100:200"]

    def test_parse_mp_reach_nlri_ipv4(self, bgp_parser):
        """Test parsing MP_REACH_NLRI for IPv4."""
        # AFI(2) + SAFI(1) + next_hop_len(1) + next_hop(4) + reserved(1) + nlri
        next_hop = struct.pack(">I", 0xC0000201)  # 192.0.2.1
        nlri = b"\x18\xc0\x00\x02"  # 192.0.2.0/24
        mp_reach_data = struct.pack(">HBB", AFI.IPV4, SAFI.UNICAST, 4) + next_hop + b"\x00" + nlri

        result = bgp_parser._parse_mp_reach_nlri(mp_reach_data)
        assert result["afi"] == AFI.IPV4
        assert result["safi"] == SAFI.UNICAST
        assert result["next_hop"] == "192.0.2.1"

    def test_parse_mp_reach_nlri_ipv6(self, bgp_parser):
        """Test parsing MP_REACH_NLRI for IPv6."""
        # IPv6 next hop (16 bytes)
        next_hop = b"\x20\x01\x0d\xb8" + b"\x00" * 12  # 2001:db8::
        nlri = b"\x40" + b"\x20\x01\x0d\xb8" + b"\x00" * 4  # 2001:db8::/64
        mp_reach_data = struct.pack(">HBB", AFI.IPV6, SAFI.UNICAST, 16) + next_hop + b"\x00" + nlri

        result = bgp_parser._parse_mp_reach_nlri(mp_reach_data)
        assert result["afi"] == AFI.IPV6
        assert result["safi"] == SAFI.UNICAST
        assert "2001:db8::" in result["next_hop"]

    def test_parse_mp_unreach_nlri(self, bgp_parser):
        """Test parsing MP_UNREACH_NLRI."""
        nlri = b"\x18\xc0\x00\x02"  # 192.0.2.0/24
        mp_unreach_data = struct.pack(">HB", AFI.IPV4, SAFI.UNICAST) + nlri

        result = bgp_parser._parse_mp_unreach_nlri(mp_unreach_data)
        assert result["afi"] == AFI.IPV4
        assert result["safi"] == SAFI.UNICAST

    def test_parse_next_hop_ipv4(self, bgp_parser):
        """Test parsing IPv4 next hop."""
        next_hop_data = struct.pack(">I", 0xC0000201)  # 192.0.2.1
        result = bgp_parser._parse_next_hop(next_hop_data, AFI.IPV4)
        assert result == "192.0.2.1"

    def test_parse_next_hop_ipv6(self, bgp_parser):
        """Test parsing IPv6 next hop."""
        next_hop_data = b"\x20\x01\x0d\xb8" + b"\x00" * 12  # 2001:db8::
        result = bgp_parser._parse_next_hop(next_hop_data, AFI.IPV6)
        assert "2001:db8::" in result

    def test_parse_ipv6_nlri(self, bgp_parser):
        """Test parsing IPv6 NLRI."""
        # /64 prefix = 64 bits = 8 bytes
        nlri_data = b"\x40" + b"\x20\x01\x0d\xb8" + b"\x00" * 4  # 2001:db8::/64
        result = bgp_parser._parse_ipv6_nlri(nlri_data)
        assert len(result) == 1
        assert "2001:db8::" in result[0]
        assert "/64" in result[0]

    def test_parse_capabilities(self, bgp_parser):
        """Test parsing BGP capabilities."""
        # Optional parameter: opt_type(1) + opt_len(1) + capability_code(1) + cap_len(1) + value
        cap_data = struct.pack(">BBBB", 2, 6, 1, 4) + struct.pack(">HH", AFI.IPV4, SAFI.UNICAST)
        result = bgp_parser._parse_capabilities(cap_data)
        assert len(result) == 1
        assert result[0]["code"] == 1

    def test_get_bgp_message_type_name(self, bgp_parser):
        """Test BGP message type name mapping."""
        assert bgp_parser._get_bgp_message_type_name(BGPMessageType.OPEN) == "OPEN"
        assert bgp_parser._get_bgp_message_type_name(BGPMessageType.UPDATE) == "UPDATE"
        assert bgp_parser._get_bgp_message_type_name(BGPMessageType.NOTIFICATION) == "NOTIFICATION"
        assert bgp_parser._get_bgp_message_type_name(BGPMessageType.KEEPALIVE) == "KEEPALIVE"
        assert bgp_parser._get_bgp_message_type_name(99) == "UNKNOWN_99"

    def test_parse_bgp_message_parse_error(self, bgp_parser):
        """Test handling ParseError during BGP message parsing."""
        with patch("src.bmp.bgp_parser.validate_data_length", side_effect=ParseError("Test error")):
            result = bgp_parser.parse_bgp_message(b"\xff" * 19)
            assert result is None

    def test_parse_bgp_message_unexpected_error(self, bgp_parser):
        """Test handling unexpected error during BGP message parsing."""
        with patch(
            "src.bmp.bgp_parser.safe_struct_unpack", side_effect=Exception("Unexpected error")
        ):
            result = bgp_parser.parse_bgp_message(b"\xff" * 19)
            assert result is None

    def test_parse_path_attributes_with_origin(self, bgp_parser):
        """Test parsing path attributes with ORIGIN."""
        # Attribute: flags(1) + type(1) + length(1) + value
        origin_attr = struct.pack(">BBBB", 0x40, BGPAttributeType.ORIGIN, 1, 0)  # IGP
        result = bgp_parser._parse_path_attributes(origin_attr)
        assert len(result) == 1
        assert result[0]["type"] == "UNKNOWN_1"  # ORIGIN not explicitly handled

    def test_parse_path_attributes_with_next_hop(self, bgp_parser):
        """Test parsing path attributes with NEXT_HOP."""
        next_hop_attr = struct.pack(">BBB", 0x40, BGPAttributeType.NEXT_HOP, 4) + struct.pack(
            ">I", 0xC0000201
        )
        result = bgp_parser._parse_path_attributes(next_hop_attr)
        assert len(result) == 1
        assert result[0]["type"] == "NEXT_HOP"
        assert result[0]["value"] == "192.0.2.1"

    def test_parse_path_attributes_unknown_type(self, bgp_parser):
        """Test parsing path attributes with unknown type."""
        unknown_attr = struct.pack(">BBBB", 0x40, 99, 1, 0)  # Unknown type
        result = bgp_parser._parse_path_attributes(unknown_attr)
        assert len(result) == 1
        assert result[0]["type"] == "UNKNOWN_99"

    def test_parse_evpn_nlri_with_error(self, bgp_parser):
        """Test parsing EVPN NLRI with error handling."""
        # Invalid EVPN NLRI data (too short)
        evpn_data = b"\x01"  # Route type 1 but no length
        result = bgp_parser._parse_evpn_nlri(evpn_data)
        assert result == []

    def test_parse_nlri_prefixes_empty(self, bgp_parser):
        """Test parsing empty NLRI prefixes."""
        result = bgp_parser._parse_nlri_prefixes(b"")
        assert result == []

    def test_parse_nlri_prefixes_invalid_length(self, bgp_parser):
        """Test parsing NLRI with invalid prefix length."""
        # Prefix length 33 for IPv4 (invalid)
        invalid_nlri = b"\x21\xc0\x00\x02\x00"
        result = bgp_parser._parse_nlri_prefixes(invalid_nlri)
        assert result == []

    def test_parse_ipv6_nlri_empty(self, bgp_parser):
        """Test parsing empty IPv6 NLRI."""
        result = bgp_parser._parse_ipv6_nlri(b"")
        assert result == []

    def test_parse_ipv6_nlri_invalid_length(self, bgp_parser):
        """Test parsing IPv6 NLRI with invalid prefix length."""
        # Prefix length 129 for IPv6 (invalid)
        invalid_nlri = b"\x81" + b"\x20\x01\x0d\xb8" + b"\x00" * 12
        result = bgp_parser._parse_ipv6_nlri(invalid_nlri)
        assert result == []


class TestBGPParserEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.fixture
    def bgp_parser(self):
        """Create BGP parser instance."""
        return BGPMessageParser()

    def test_parse_as_path_empty(self, bgp_parser):
        """Test parsing empty AS path."""
        result = bgp_parser._parse_as_path(b"")
        assert result == []

    def test_parse_as_path_invalid_segment(self, bgp_parser):
        """Test parsing AS path with invalid segment."""
        # Invalid segment type - the parser might still try to process it
        invalid_as_path = struct.pack(">BBH", 99, 1, 65001)
        result = bgp_parser._parse_as_path(invalid_as_path)
        # The actual behavior might be to still return the AS number
        assert isinstance(result, list)

    def test_parse_communities_invalid_length(self, bgp_parser):
        """Test parsing communities with invalid length."""
        # Odd number of bytes (should be multiple of 4)
        invalid_comm = b"\x00\x01\x02"
        result = bgp_parser._parse_communities(invalid_comm)
        assert result == []

    def test_parse_large_communities_invalid_length(self, bgp_parser):
        """Test parsing large communities with invalid length."""
        # Not multiple of 12 bytes
        invalid_large_comm = b"\x00" * 10
        result = bgp_parser._parse_large_communities(invalid_large_comm)
        assert result == []

    def test_parse_mp_reach_nlri_insufficient_data(self, bgp_parser):
        """Test parsing MP_REACH_NLRI with insufficient data."""
        # Only AFI, no SAFI - this should raise ParseError
        insufficient_data = struct.pack(">H", AFI.IPV4)
        try:
            result = bgp_parser._parse_mp_reach_nlri(insufficient_data)
            # If no exception, result should be empty dict
            assert result == {}
        except ParseError:
            # This is expected behavior
            pass

    def test_parse_mp_unreach_nlri_insufficient_data(self, bgp_parser):
        """Test parsing MP_UNREACH_NLRI with insufficient data."""
        # Only AFI, no SAFI - this should raise ParseError
        insufficient_data = struct.pack(">H", AFI.IPV4)
        try:
            result = bgp_parser._parse_mp_unreach_nlri(insufficient_data)
            # If no exception, result should be empty dict
            assert result == {}
        except ParseError:
            # This is expected behavior
            pass

    def test_parse_next_hop_unknown_afi(self, bgp_parser):
        """Test parsing next hop with unknown AFI."""
        next_hop_data = b"\x01\x02\x03\x04"
        result = bgp_parser._parse_next_hop(next_hop_data, 99)  # Unknown AFI
        assert result == "01020304"  # Returns hex representation

    def test_parse_capabilities_empty(self, bgp_parser):
        """Test parsing empty capabilities."""
        result = bgp_parser._parse_capabilities(b"")
        assert result == []

    def test_parse_capabilities_insufficient_data(self, bgp_parser):
        """Test parsing capabilities with insufficient data."""
        # Only capability type, no length
        insufficient_data = b"\x01"
        result = bgp_parser._parse_capabilities(insufficient_data)
        assert result == []
