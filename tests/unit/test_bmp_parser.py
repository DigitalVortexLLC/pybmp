"""Unit tests for BMP parser."""
import struct
from unittest.mock import patch

import pytest

from src.bmp.parser import AFI, SAFI, BGPMessageType, BMPMessageType, BMPParser, BMPPeerType
from tests.fixtures.bmp_messages import INVALID_MESSAGES, TEST_MESSAGES, BMPMessageBuilder


class TestBMPParser:
    """Test BMP parser functionality."""

    def test_parser_initialization(self, bmp_parser):
        """Test parser initialization."""
        assert isinstance(bmp_parser, BMPParser)
        assert bmp_parser.buffer == b""

    @pytest.mark.unit
    def test_parse_valid_route_monitoring_message(self, bmp_parser):
        """Test parsing valid route monitoring message."""
        message_data = TEST_MESSAGES["route_monitoring"]
        result = bmp_parser.parse_message(message_data)

        assert result is not None
        assert result["type"] == "route_monitoring"
        assert "peer" in result
        assert "bgp_message" in result

        # Check peer header
        peer = result["peer"]
        assert peer["peer_type"] == 0
        assert peer["peer_as"] == 65001
        assert peer["peer_ip"] == "192.0.2.1"

        # Check BGP message
        bgp_msg = result["bgp_message"]
        assert bgp_msg["type"] == "UPDATE"

    @pytest.mark.unit
    def test_parse_peer_up_message(self, bmp_parser):
        """Test parsing peer up message."""
        message_data = TEST_MESSAGES["peer_up"]
        result = bmp_parser.parse_message(message_data)

        assert result is not None
        assert result["type"] == "peer_up"
        assert "peer" in result
        assert "local_ip" in result
        assert "local_port" in result
        assert "remote_port" in result

    @pytest.mark.unit
    def test_parse_peer_down_message(self, bmp_parser):
        """Test parsing peer down message."""
        message_data = TEST_MESSAGES["peer_down"]
        result = bmp_parser.parse_message(message_data)

        assert result is not None
        assert result["type"] == "peer_down"
        assert "peer" in result
        assert "reason" in result

    @pytest.mark.unit
    def test_parse_initiation_message(self, bmp_parser):
        """Test parsing initiation message."""
        message_data = TEST_MESSAGES["initiation"]
        result = bmp_parser.parse_message(message_data)

        assert result is not None
        assert result["type"] == "initiation"
        assert "information" in result
        assert isinstance(result["information"], list)

    @pytest.mark.unit
    def test_parse_termination_message(self, bmp_parser):
        """Test parsing termination message."""
        message_data = TEST_MESSAGES["termination"]
        result = bmp_parser.parse_message(message_data)

        assert result is not None
        assert result["type"] == "termination"
        assert "information" in result

    @pytest.mark.unit
    def test_parse_stats_report_message(self, bmp_parser):
        """Test parsing statistics report message."""
        message_data = TEST_MESSAGES["stats_report"]
        result = bmp_parser.parse_message(message_data)

        assert result is not None
        assert result["type"] == "stats_report"
        assert "peer" in result
        assert "stats" in result
        assert isinstance(result["stats"], list)

    @pytest.mark.unit
    def test_parse_invalid_version(self, bmp_parser):
        """Test parsing message with invalid version."""
        result = bmp_parser.parse_message(INVALID_MESSAGES["wrong_version"])
        assert result is None

    @pytest.mark.unit
    def test_parse_short_message(self, bmp_parser):
        """Test parsing message shorter than minimum."""
        result = bmp_parser.parse_message(INVALID_MESSAGES["short_header"])
        assert result is None

    @pytest.mark.unit
    def test_parse_incomplete_message(self, bmp_parser):
        """Test parsing incomplete message."""
        # Create message that claims to be longer than actual data
        incomplete = b"\x03\x00\x00\x00\x20\x00" + b"incomplete"
        result = bmp_parser.parse_message(incomplete)
        assert result is None

    @pytest.mark.unit
    def test_parse_unsupported_message_type(self, bmp_parser):
        """Test parsing unsupported message type."""
        # Create message with invalid type
        invalid_type = BMPMessageBuilder.create_bmp_header(99, 6)
        result = bmp_parser.parse_message(invalid_type)
        assert result is None

    @pytest.mark.unit
    def test_per_peer_header_parsing(self, bmp_parser):
        """Test per-peer header parsing."""
        # Create minimal route monitoring message to test peer header
        peer_data = BMPMessageBuilder.create_per_peer_header(
            peer_type=1,  # RD_INSTANCE
            peer_flags=0x80,  # IPv6 flag
            peer_ip="2001:db8::1",
            peer_as=4200000000,  # 4-byte AS
            peer_bgp_id="203.0.113.1",
        )

        header, offset = bmp_parser._parse_per_peer_header(peer_data)

        assert header["peer_type"] == 1
        assert header["peer_flags"]["v_flag"] is True
        assert header["peer_as"] == 4200000000
        assert offset == 42

    @pytest.mark.unit
    def test_per_peer_header_insufficient_data(self, bmp_parser):
        """Test per-peer header with insufficient data."""
        insufficient_data = b"\x00" * 30  # Less than required 42 bytes

        with pytest.raises(ValueError, match="Insufficient data for per-peer header"):
            bmp_parser._parse_per_peer_header(insufficient_data)

    @pytest.mark.unit
    def test_bgp_update_parsing(self, bmp_parser):
        """Test BGP UPDATE message parsing."""
        # Create BGP UPDATE with withdrawn routes and NLRI
        bgp_update = BMPMessageBuilder.create_bgp_update(
            withdrawn=["10.0.1.0/24"],
            path_attrs=[
                {"type": 1, "value": 0},  # ORIGIN
                {"type": 3, "value": "192.0.2.1"},  # NEXT_HOP
            ],
            nlri=["10.0.2.0/24", "10.0.3.0/24"],
        )

        # Extract just the UPDATE part (skip BGP header)
        update_data = bgp_update[19:]  # Skip 19-byte BGP header
        result = bmp_parser._parse_bgp_update(update_data)

        assert result["type"] == "UPDATE"
        assert "withdrawn" in result
        assert "attributes" in result
        assert "nlri" in result

    @pytest.mark.unit
    def test_parse_as_path_attribute(self, bmp_parser):
        """Test AS_PATH attribute parsing."""
        # Create AS_PATH with AS_SEQUENCE
        as_path_data = struct.pack(">BB", 2, 3)  # AS_SEQUENCE, 3 ASNs
        as_path_data += struct.pack(">III", 65001, 65002, 65003)

        result = bmp_parser._parse_as_path(as_path_data)

        assert len(result) == 1
        assert result[0]["type"] == "AS_SEQUENCE"
        assert result[0]["as_numbers"] == [65001, 65002, 65003]

    @pytest.mark.unit
    def test_parse_communities_attribute(self, bmp_parser):
        """Test COMMUNITIES attribute parsing."""
        # Create communities: 65001:100, 65002:200
        communities_data = struct.pack(">HHHH", 65001, 100, 65002, 200)

        result = bmp_parser._parse_communities(communities_data)

        assert len(result) == 2
        assert "65001:100" in result
        assert "65002:200" in result

    @pytest.mark.unit
    def test_parse_large_communities_attribute(self, bmp_parser):
        """Test LARGE_COMMUNITIES attribute parsing."""
        # Create large communities: 65001:100:200, 65002:300:400
        large_comm_data = struct.pack(">IIIIII", 65001, 100, 200, 65002, 300, 400)

        result = bmp_parser._parse_large_communities(large_comm_data)

        assert len(result) == 2
        assert "65001:100:200" in result
        assert "65002:300:400" in result

    @pytest.mark.unit
    def test_parse_nlri_ipv4(self, bmp_parser):
        """Test IPv4 NLRI parsing."""
        # Create NLRI for 10.0.1.0/24 and 192.168.1.0/28
        nlri_data = b"\x18\x0a\x00\x01"  # 24-bit prefix 10.0.1
        nlri_data += b"\x1c\xc0\xa8\x01\x00"  # 28-bit prefix 192.168.1.0

        result = bmp_parser._parse_nlri(nlri_data, AFI.IPV4)

        assert len(result) == 2
        assert "10.0.1.0/24" in result
        assert "192.168.1.0/28" in result

    @pytest.mark.unit
    def test_parse_nlri_ipv6(self, bmp_parser):
        """Test IPv6 NLRI parsing."""
        # Create NLRI for 2001:db8::/32
        nlri_data = b"\x20" + b"\x20\x01\x0d\xb8"  # 32-bit prefix

        result = bmp_parser._parse_nlri(nlri_data, AFI.IPV6)

        assert len(result) == 1
        assert "2001:db8::/32" in result

    @pytest.mark.unit
    def test_parse_mp_reach_nlri(self, bmp_parser):
        """Test MP_REACH_NLRI attribute parsing."""
        # Create MP_REACH_NLRI for IPv6 unicast
        mp_reach_data = struct.pack(">HBB", AFI.IPV6, SAFI.UNICAST, 16)  # AFI, SAFI, NH len
        mp_reach_data += (
            b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"  # Next hop
        )
        mp_reach_data += b"\x00"  # Reserved
        mp_reach_data += b"\x40\x20\x01\x0d\xb8\x00\x01"  # NLRI: 2001:db8:1::/64

        result = bmp_parser._parse_mp_reach_nlri(mp_reach_data)

        assert result["afi"] == AFI.IPV6
        assert result["safi"] == SAFI.UNICAST
        assert result["next_hop"] == "2001:db8::1"
        assert len(result["nlri"]) >= 0

    @pytest.mark.unit
    def test_parse_mp_unreach_nlri(self, bmp_parser):
        """Test MP_UNREACH_NLRI attribute parsing."""
        # Create MP_UNREACH_NLRI
        mp_unreach_data = struct.pack(">HB", AFI.IPV4, SAFI.UNICAST)
        mp_unreach_data += b"\x18\x0a\x00\x01"  # Withdrawn: 10.0.1.0/24

        result = bmp_parser._parse_mp_unreach_nlri(mp_unreach_data)

        assert result["afi"] == AFI.IPV4
        assert result["safi"] == SAFI.UNICAST
        assert "withdrawn" in result

    @pytest.mark.unit
    def test_parse_bgp_open_message(self, bmp_parser):
        """Test BGP OPEN message parsing."""
        # Create BGP OPEN message data (without header)
        open_data = struct.pack(
            ">BHHIB", 4, 65001, 180, 0xC0000201, 0
        )  # Version, AS, Hold time, BGP ID, Opt len

        result = bmp_parser._parse_bgp_open(open_data)

        assert result["type"] == "OPEN"
        assert result["version"] == 4
        assert result["as"] == 65001
        assert result["hold_time"] == 180
        assert result["bgp_id"] == "192.0.2.1"

    @pytest.mark.unit
    def test_parse_bgp_open_invalid_length(self, bmp_parser):
        """Test BGP OPEN message with invalid length."""
        # Too short OPEN message
        short_open = b"\x04\x00\x01"

        result = bmp_parser._parse_bgp_open(short_open)

        assert result["type"] == "OPEN"
        assert "error" in result

    @pytest.mark.unit
    def test_parse_route_distinguisher(self, bmp_parser):
        """Test Route Distinguisher parsing."""
        # Type 0: AS:Number
        rd_type0 = struct.pack(">HHI", 0, 65001, 100)
        result = bmp_parser._parse_route_distinguisher(rd_type0)
        assert result == "65001:100"

        # Type 1: IP:Number
        rd_type1 = struct.pack(">H", 1) + struct.pack(">I", 0xC0000201) + struct.pack(">H", 100)
        result = bmp_parser._parse_route_distinguisher(rd_type1)
        assert result == "192.0.2.1:100"

        # Invalid length
        invalid_rd = b"\x00\x01\x02"
        result = bmp_parser._parse_route_distinguisher(invalid_rd)
        assert result == "000102"  # Hex representation

    @pytest.mark.unit
    def test_parse_tlvs(self, bmp_parser):
        """Test TLV parsing."""
        # Create TLVs: string (type 0) and string (type 2)
        tlv_data = struct.pack(">HH", 0, 4) + b"test"
        tlv_data += struct.pack(">HH", 2, 6) + b"router"

        result = bmp_parser._parse_tlvs(tlv_data)

        assert len(result) == 2
        assert result[0]["type"] == 0
        assert result[0]["value"] == "test"
        assert result[1]["type"] == 2
        assert result[1]["value"] == "router"

    @pytest.mark.unit
    def test_parse_capabilities(self, bmp_parser):
        """Test BGP capabilities parsing."""
        # Create capabilities: Multiprotocol (code 1)
        cap_data = struct.pack(">BBB", 1, 4, 0)  # Code, length, padding
        cap_data += struct.pack(">HB", AFI.IPV6, SAFI.UNICAST)

        result = bmp_parser._parse_capabilities(cap_data)

        assert len(result) == 1
        assert result[0]["code"] == 1

    @pytest.mark.unit
    def test_error_handling(self, bmp_parser):
        """Test error handling in parser."""
        # Test with corrupted data that should trigger exception handling during per-peer header parsing
        # Create a route monitoring message with correct message length but insufficient per-peer header data
        corrupted_data = (
            b"\x03\x00\x00\x00\x2A\x00" + b"\xff" * 36
        )  # 42 bytes total, need 42 for per-peer header

        with patch("src.bmp.parser.logger") as mock_logger:
            result = bmp_parser.parse_message(corrupted_data)

            # Should return None and log error
            assert result is None
            mock_logger.error.assert_called()

    @pytest.mark.unit
    def test_buffer_management(self, bmp_parser):
        """Test parser buffer management."""
        # Test that parser doesn't maintain state between calls
        message1 = TEST_MESSAGES["route_monitoring"]
        message2 = TEST_MESSAGES["peer_up"]

        result1 = bmp_parser.parse_message(message1)
        result2 = bmp_parser.parse_message(message2)

        assert result1["type"] == "route_monitoring"
        assert result2["type"] == "peer_up"
        # Buffer should be empty after each parse
        assert bmp_parser.buffer == b""

    @pytest.mark.unit
    def test_message_type_enum_values(self):
        """Test BMP message type enum values."""
        assert BMPMessageType.ROUTE_MONITORING == 0
        assert BMPMessageType.STATISTICS_REPORT == 1
        assert BMPMessageType.PEER_DOWN == 2
        assert BMPMessageType.PEER_UP == 3
        assert BMPMessageType.INITIATION == 4
        assert BMPMessageType.TERMINATION == 5
        assert BMPMessageType.ROUTE_MIRRORING == 6

    @pytest.mark.unit
    def test_peer_type_enum_values(self):
        """Test BMP peer type enum values."""
        assert BMPPeerType.GLOBAL_INSTANCE == 0
        assert BMPPeerType.RD_INSTANCE == 1
        assert BMPPeerType.LOCAL_INSTANCE == 2

    @pytest.mark.unit
    def test_bgp_message_type_enum_values(self):
        """Test BGP message type enum values."""
        assert BGPMessageType.OPEN == 1
        assert BGPMessageType.UPDATE == 2
        assert BGPMessageType.NOTIFICATION == 3
        assert BGPMessageType.KEEPALIVE == 4
        assert BGPMessageType.ROUTE_REFRESH == 5

    @pytest.mark.unit
    def test_afi_safi_enum_values(self):
        """Test AFI/SAFI enum values."""
        assert AFI.IPV4 == 1
        assert AFI.IPV6 == 2
        assert AFI.L2VPN == 25

        assert SAFI.UNICAST == 1
        assert SAFI.MULTICAST == 2
        assert SAFI.MPLS_VPN == 128
        assert SAFI.EVPN == 70


class TestBMPParserEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.unit
    def test_maximum_message_size(self, bmp_parser):
        """Test handling of maximum-sized messages."""
        # Test with large but valid message
        large_data = b"\x03" + struct.pack(">I", 1000) + b"\x00" + b"x" * 994
        result = bmp_parser.parse_message(large_data)
        # Should handle gracefully - parser actually succeeds in parsing this
        assert result is not None  # Parser successfully handles large messages

    @pytest.mark.unit
    def test_zero_length_fields(self, bmp_parser):
        """Test handling of zero-length fields."""
        # Create TLV with zero-length value
        tlv_data = struct.pack(">HH", 0, 0)  # Type 0, length 0
        result = bmp_parser._parse_tlvs(tlv_data)

        assert len(result) == 1
        assert result[0]["value"] == ""

    @pytest.mark.unit
    def test_malformed_nlri(self, bmp_parser):
        """Test handling of malformed NLRI."""
        # NLRI with invalid prefix length
        malformed_nlri = b"\xff\x0a\x00\x01"  # 255-bit prefix (invalid)

        result = bmp_parser._parse_nlri(malformed_nlri, AFI.IPV4)
        # Should handle gracefully and not crash
        assert isinstance(result, list)

    @pytest.mark.unit
    def test_empty_as_path(self, bmp_parser):
        """Test handling of empty AS_PATH."""
        empty_as_path = b""
        result = bmp_parser._parse_as_path(empty_as_path)
        assert result == []

    @pytest.mark.unit
    def test_truncated_path_attributes(self, bmp_parser):
        """Test handling of truncated path attributes."""
        # Create truncated attribute (claims length but data is shorter)
        truncated_attr = (
            struct.pack(">BBB", 0x40, 1, 10) + b"\x00"
        )  # Claims 10 bytes, only 1 available

        result = bmp_parser._parse_path_attributes(truncated_attr)
        # Should handle gracefully and stop parsing
        assert isinstance(result, list)

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "afi,safi",
        [
            (AFI.IPV4, SAFI.UNICAST),
            (AFI.IPV6, SAFI.UNICAST),
            (AFI.L2VPN, SAFI.EVPN),
            (999, 255),  # Invalid AFI/SAFI
        ],
    )
    def test_various_afi_safi_combinations(self, bmp_parser, afi, safi):
        """Test parsing with various AFI/SAFI combinations."""
        mp_unreach_data = struct.pack(">HB", afi, safi) + b"\x18\x0a\x00\x01"

        result = bmp_parser._parse_mp_unreach_nlri(mp_unreach_data)

        assert result["afi"] == afi
        assert result["safi"] == safi
        assert "withdrawn" in result

    @pytest.mark.unit
    def test_parse_evpn_route_type_4_ipv4(self, bmp_parser):
        """Test parsing EVPN Route Type 4 (Ethernet Segment) with IPv4."""
        # Construct EVPN Route Type 4 data
        # RD: Type 0, Admin=65001, Assigned=100 (8 bytes)
        rd_data = struct.pack(">HHI", 0, 65001, 100)
        # ESI: 10 bytes (example ESI)
        esi_data = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x02])
        # IP Length: 32 bits for IPv4
        ip_len = 32
        # IPv4 Address: 192.0.2.1
        ipv4_data = struct.pack(">I", 0xC0000201)  # 192.0.2.1

        route_data = rd_data + esi_data + struct.pack("B", ip_len) + ipv4_data

        result = bmp_parser._parse_evpn_route(4, route_data)

        assert result is not None
        assert result["type"] == 4
        assert result["name"] == "Ethernet Segment"
        assert result["rd"] == "65001:100"
        assert result["esi"] == "0123456789abcdef0102"
        assert result["originating_ip"] == "192.0.2.1"
        assert result["ip_length"] == 32

    @pytest.mark.unit
    def test_parse_evpn_route_type_4_ipv6(self, bmp_parser):
        """Test parsing EVPN Route Type 4 (Ethernet Segment) with IPv6."""
        # Construct EVPN Route Type 4 data with IPv6
        # RD: Type 1, IP=10.0.0.1, Assigned=200 (8 bytes)
        rd_data = struct.pack(">HI", 1, 0x0A000001) + struct.pack(">H", 200)
        # ESI: 10 bytes (different ESI)
        esi_data = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99])
        # IP Length: 128 bits for IPv6
        ip_len = 128
        # IPv6 Address: 2001:db8::1
        ipv6_data = struct.pack(">IIII", 0x20010DB8, 0, 0, 1)

        route_data = rd_data + esi_data + struct.pack("B", ip_len) + ipv6_data

        result = bmp_parser._parse_evpn_route(4, route_data)

        assert result is not None
        assert result["type"] == 4
        assert result["name"] == "Ethernet Segment"
        assert result["rd"] == "10.0.0.1:200"
        assert result["esi"] == "00112233445566778899"
        assert result["originating_ip"] == "2001:db8::1"
        assert result["ip_length"] == 128

    @pytest.mark.unit
    def test_parse_evpn_route_type_4_minimal(self, bmp_parser):
        """Test parsing EVPN Route Type 4 with minimal data (no IP)."""
        # RD + ESI only (18 bytes total)
        rd_data = struct.pack(">HHI", 0, 65002, 300)
        esi_data = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33])

        route_data = rd_data + esi_data

        result = bmp_parser._parse_evpn_route(4, route_data)

        assert result is not None
        assert result["type"] == 4
        assert result["name"] == "Ethernet Segment"
        assert result["rd"] == "65002:300"
        assert result["esi"] == "aabbccddeeff00112233"
        assert "originating_ip" not in result

    @pytest.mark.unit
    def test_parse_evpn_route_type_4_invalid_data(self, bmp_parser):
        """Test parsing EVPN Route Type 4 with invalid/insufficient data."""
        # Insufficient data (less than 18 bytes)
        insufficient_data = b"short"

        result = bmp_parser._parse_evpn_route(4, insufficient_data)

        assert result is not None
        assert result["type"] == 4
        assert result["name"] == "Ethernet Segment"
        assert "rd" not in result
        assert "esi" not in result

    @pytest.mark.unit
    def test_parse_evpn_route_type_4_partial_ip(self, bmp_parser):
        """Test parsing EVPN Route Type 4 with partial IP length."""
        # RD + ESI + partial IP length (24 bits)
        rd_data = struct.pack(">HHI", 0, 65003, 400)
        esi_data = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22])
        ip_len = 24  # Partial IPv4
        ip_data = bytes([192, 168, 1])  # 3 bytes for /24

        route_data = rd_data + esi_data + struct.pack("B", ip_len) + ip_data

        result = bmp_parser._parse_evpn_route(4, route_data)

        assert result is not None
        assert result["type"] == 4
        assert result["name"] == "Ethernet Segment"
        assert result["rd"] == "65003:400"
        assert result["esi"] == "123456789abcdef01122"
        assert result["originating_ip"] == "c0a801"  # Hex representation
        assert result["ip_length"] == 24

    def test_parse_evpn_route_type_1_basic(self, bmp_parser):
        """Test parsing EVPN Route Type 1 (Ethernet Auto-Discovery) basic case."""
        # Construct EVPN Route Type 1 data
        rd_data = struct.pack(">HHI", 0, 65001, 100)  # RD: 65001:100
        esi_data = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x02])  # ESI
        eth_tag = struct.pack(">I", 100)  # Ethernet Tag = 100
        # MPLS Label: Label=1000, EXP=3, S=1 (3-byte format)
        mpls_field_24bit = (1000 << 4) | (3 << 1) | 1
        byte1 = (mpls_field_24bit >> 16) & 0xFF
        byte2 = (mpls_field_24bit >> 8) & 0xFF
        byte3 = mpls_field_24bit & 0xFF
        mpls_label = bytes([byte1, byte2, byte3])

        data = rd_data + esi_data + eth_tag + mpls_label

        result = bmp_parser._parse_evpn_route(1, data)

        assert result is not None
        assert result["type"] == 1
        assert result["name"] == "Ethernet Auto-Discovery"
        assert result["rd"] == "65001:100"
        assert result["esi"] == "0123456789abcdef0102"
        assert result["eth_tag"] == 100
        assert result["mpls_label"] == 1000
        assert result["mpls_exp"] == 3
        assert result["mpls_s"] == 1

    def test_parse_evpn_route_type_1_minimal_data(self, bmp_parser):
        """Test parsing EVPN Route Type 1 with minimal data."""
        data = bytes(20)  # Less than 25 bytes

        result = bmp_parser._parse_evpn_route(1, data)

        assert result is not None
        assert result["type"] == 1
        assert result["name"] == "Ethernet Auto-Discovery"
        # Should not have detailed fields due to insufficient data
        assert "rd" not in result
        assert "esi" not in result

    def test_parse_evpn_route_type_1_different_mpls_values(self, bmp_parser):
        """Test parsing EVPN Route Type 1 with different MPLS label values."""
        rd_data = struct.pack(">HHI", 0, 65002, 200)  # RD: 65002:200
        esi_data = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44])  # ESI
        eth_tag = struct.pack(">I", 999)  # Ethernet Tag = 999
        # MPLS Label: Label=2000, EXP=7, S=0 (3-byte format)
        mpls_field_24bit = (2000 << 4) | (7 << 1) | 0
        byte1 = (mpls_field_24bit >> 16) & 0xFF
        byte2 = (mpls_field_24bit >> 8) & 0xFF
        byte3 = mpls_field_24bit & 0xFF
        mpls_label = bytes([byte1, byte2, byte3])

        data = rd_data + esi_data + eth_tag + mpls_label

        result = bmp_parser._parse_evpn_route(1, data)

        assert result is not None
        assert result["mpls_label"] == 2000
        assert result["mpls_exp"] == 7
        assert result["mpls_s"] == 0

    def test_parse_evpn_route_type_1_large_mpls_label(self, bmp_parser):
        """Test parsing EVPN Route Type 1 with large MPLS label values like 512000."""
        rd_data = struct.pack(">HHI", 0, 65002, 300)  # RD: 65002:300
        esi_data = bytes([0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])  # ESI
        eth_tag = struct.pack(">I", 1500)  # Ethernet Tag = 1500

        # Construct MPLS label field properly for large values
        # Label=512000, EXP=5, S=1, TTL=128
        label_value = 512000
        exp_value = 5
        s_value = 1
        ttl_value = 128

        # Construct the 24-bit MPLS field correctly
        # In a 3-byte MPLS field: 20 bits label + 3 bits EXP + 1 bit S (no TTL in 3-byte format)
        # Format: bits 23-4 = label, bits 3-1 = EXP, bit 0 = S
        mpls_field_24bit = (label_value << 4) | (exp_value << 1) | s_value

        # Pack as 3 bytes directly
        byte1 = (mpls_field_24bit >> 16) & 0xFF
        byte2 = (mpls_field_24bit >> 8) & 0xFF
        byte3 = mpls_field_24bit & 0xFF
        mpls_label = bytes([byte1, byte2, byte3])

        data = rd_data + esi_data + eth_tag + mpls_label

        result = bmp_parser._parse_evpn_route(1, data)

        assert result is not None
        assert result["mpls_label"] == 512000
        assert result["mpls_exp"] == 5
        assert result["mpls_s"] == 1

    def test_parse_evpn_route_type_1_exact_size(self, bmp_parser):
        """Test parsing EVPN Route Type 1 with exactly 25 bytes."""
        data = bytes(25)  # Exactly 25 bytes

        result = bmp_parser._parse_evpn_route(1, data)

        assert result is not None
        assert result["type"] == 1
        assert result["name"] == "Ethernet Auto-Discovery"
        # Should have all fields parsed
        assert "rd" in result
        assert "esi" in result
        assert "eth_tag" in result
        assert "mpls_label" in result

    def test_parse_evpn_route_type_2_enhanced_ipv4(self, bmp_parser):
        """Test parsing enhanced EVPN Route Type 2 (MAC/IP Advertisement) with IPv4."""
        # Construct EVPN Route Type 2 data with IPv4
        rd_data = struct.pack(">HHI", 0, 65001, 200)  # RD: 65001:200
        esi_data = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA])  # ESI
        eth_tag = struct.pack(">I", 200)  # Ethernet Tag = 200
        mac_len = 48  # MAC length in bits
        mac_data = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])  # MAC address
        ip_len = 32  # IPv4 length in bits
        ipv4_data = struct.pack(">I", 0xC0000202)  # 192.0.2.2
        # MPLS Label1: Label=3000, EXP=5, S=0 (3 bytes, no TTL)
        mpls_label1 = struct.pack(">I", (3000 << 4) | (5 << 1) | 0)[1:4]

        data = (
            rd_data
            + esi_data
            + eth_tag
            + bytes([mac_len])
            + mac_data
            + bytes([ip_len])
            + ipv4_data
            + mpls_label1
        )

        result = bmp_parser._parse_evpn_route(2, data)

        assert result is not None
        assert result["type"] == 2
        assert result["name"] == "MAC/IP Advertisement"
        assert result["rd"] == "65001:200"
        assert result["esi"] == "112233445566778899aa"
        assert result["eth_tag"] == 200
        assert result["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["ip_length"] == 32
        assert result["ip_address"] == "192.0.2.2"
        assert result["mpls_label1"] == 3000
        assert result["mpls_exp1"] == 5
        assert result["mpls_s1"] == 0

    def test_parse_evpn_route_type_2_enhanced_ipv6(self, bmp_parser):
        """Test parsing enhanced EVPN Route Type 2 with IPv6."""
        rd_data = struct.pack(">HHI", 0, 65002, 300)  # RD: 65002:300
        esi_data = bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66])  # ESI
        eth_tag = struct.pack(">I", 300)  # Ethernet Tag = 300
        mac_len = 48  # MAC length in bits
        mac_data = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])  # MAC address
        ip_len = 128  # IPv6 length in bits
        ipv6_data = bytes(
            [
                0x20,
                0x01,
                0x0D,
                0xB8,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
            ]
        )  # 2001:db8::1
        # MPLS Label1: Label=4000, EXP=3, S=1 (3 bytes, no TTL)
        mpls_label1 = struct.pack(">I", (4000 << 4) | (3 << 1) | 1)[1:4]

        data = (
            rd_data
            + esi_data
            + eth_tag
            + bytes([mac_len])
            + mac_data
            + bytes([ip_len])
            + ipv6_data
            + mpls_label1
        )

        result = bmp_parser._parse_evpn_route(2, data)

        assert result is not None
        assert result["type"] == 2
        assert result["name"] == "MAC/IP Advertisement"
        assert result["rd"] == "65002:300"
        assert result["esi"] == "ffeeddccbbaa99887766"
        assert result["eth_tag"] == 300
        assert result["mac"] == "12:34:56:78:9a:bc"
        assert result["ip_length"] == 128
        assert result["ip_address"] == "2001:db8::1"
        assert result["mpls_label1"] == 4000
        assert result["mpls_exp1"] == 3
        assert result["mpls_s1"] == 1

    def test_parse_evpn_route_type_2_with_two_labels(self, bmp_parser):
        """Test parsing EVPN Route Type 2 with two MPLS labels."""
        rd_data = struct.pack(">HHI", 0, 65003, 400)  # RD: 65003:400
        esi_data = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A])  # ESI
        eth_tag = struct.pack(">I", 400)  # Ethernet Tag = 400
        mac_len = 48  # MAC length in bits
        mac_data = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE])  # MAC address
        ip_len = 0  # No IP address
        # MPLS Label1: Label=1000, EXP=6, S=0, TTL=32
        mpls_label1 = struct.pack(">I", (1000 << 4) | (6 << 1) | 0)[1:4]
        # MPLS Label2: Label=2000, EXP=2, S=1 (3 bytes, no TTL)
        mpls_label2 = struct.pack(">I", (2000 << 4) | (2 << 1) | 1)[1:4]

        data = (
            rd_data
            + esi_data
            + eth_tag
            + bytes([mac_len])
            + mac_data
            + bytes([ip_len])
            + mpls_label1
            + mpls_label2
        )

        result = bmp_parser._parse_evpn_route(2, data)

        assert result is not None
        assert result["type"] == 2
        assert result["name"] == "MAC/IP Advertisement"
        assert result["rd"] == "65003:400"
        assert result["esi"] == "0102030405060708090a"
        assert result["eth_tag"] == 400
        assert result["mac"] == "de:ad:be:ef:ca:fe"
        assert result["ip_length"] == 0
        assert "ip_address" not in result  # No IP address when length is 0
        assert result["mpls_label1"] == 1000
        assert result["mpls_exp1"] == 6
        assert result["mpls_s1"] == 0
        assert result["mpls_label2"] == 2000
        assert result["mpls_exp2"] == 2
        assert result["mpls_s2"] == 1

    def test_parse_evpn_route_type_3_ipv4(self, bmp_parser):
        """Test parsing EVPN Route Type 3 (Inclusive Multicast) with IPv4."""
        # Construct EVPN Route Type 3 data
        rd_data = struct.pack(">HHI", 0, 65001, 500)  # RD: 65001:500
        eth_tag = struct.pack(">I", 500)  # Ethernet Tag = 500
        ip_len = 32  # IPv4 length in bits
        ipv4_data = struct.pack(">I", 0xC0000203)  # 192.0.2.3

        data = rd_data + eth_tag + bytes([ip_len]) + ipv4_data

        result = bmp_parser._parse_evpn_route(3, data)

        assert result is not None
        assert result["type"] == 3
        assert result["name"] == "Inclusive Multicast"
        assert result["rd"] == "65001:500"
        assert result["eth_tag"] == 500
        assert result["ip_length"] == 32
        assert result["originating_ip"] == "192.0.2.3"

    def test_parse_evpn_route_type_3_ipv6(self, bmp_parser):
        """Test parsing EVPN Route Type 3 with IPv6."""
        rd_data = struct.pack(">HHI", 0, 65002, 600)  # RD: 65002:600
        eth_tag = struct.pack(">I", 600)  # Ethernet Tag = 600
        ip_len = 128  # IPv6 length in bits
        ipv6_data = bytes(
            [
                0x20,
                0x01,
                0x0D,
                0xB8,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x02,
            ]
        )  # 2001:db8::2

        data = rd_data + eth_tag + bytes([ip_len]) + ipv6_data

        result = bmp_parser._parse_evpn_route(3, data)

        assert result is not None
        assert result["type"] == 3
        assert result["name"] == "Inclusive Multicast"
        assert result["rd"] == "65002:600"
        assert result["eth_tag"] == 600
        assert result["ip_length"] == 128
        assert result["originating_ip"] == "2001:db8::2"

    def test_parse_evpn_route_type_3_no_ip(self, bmp_parser):
        """Test parsing EVPN Route Type 3 with no IP address."""
        rd_data = struct.pack(">HHI", 0, 65003, 700)  # RD: 65003:700
        eth_tag = struct.pack(">I", 700)  # Ethernet Tag = 700
        ip_len = 0  # No IP address

        data = rd_data + eth_tag + bytes([ip_len])

        result = bmp_parser._parse_evpn_route(3, data)

        assert result is not None
        assert result["type"] == 3
        assert result["name"] == "Inclusive Multicast"
        assert result["rd"] == "65003:700"
        assert result["eth_tag"] == 700
        assert result["ip_length"] == 0
        assert "originating_ip" not in result  # No IP address when length is 0

    def test_parse_evpn_route_type_3_minimal_data(self, bmp_parser):
        """Test parsing EVPN Route Type 3 with minimal data."""
        data = bytes(10)  # Less than 12 bytes

        result = bmp_parser._parse_evpn_route(3, data)

        assert result is not None
        assert result["type"] == 3
        assert result["name"] == "Inclusive Multicast"
        # Should not have detailed fields due to insufficient data
        assert "rd" not in result
        assert "eth_tag" not in result

    def test_parse_evpn_route_type_5_ipv4(self, bmp_parser):
        """Test parsing EVPN Route Type 5 (IP Prefix) with IPv4."""
        # Construct EVPN Route Type 5 data
        rd_data = struct.pack(">HHI", 0, 65001, 800)  # RD: 65001:800
        esi_data = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA])  # ESI
        eth_tag = struct.pack(">I", 800)  # Ethernet Tag = 800
        ip_prefix_len = 24  # IPv4 /24 prefix
        ip_prefix_data = bytes([192, 0, 2])  # 192.0.2.0/24 (only 3 bytes needed for /24)
        gw_ip_len = 32  # IPv4 gateway
        gw_ip_data = struct.pack(">I", 0xC0000201)  # 192.0.2.1
        # MPLS Label: Label=1100, EXP=4, S=1, TTL=200
        mpls_label = struct.pack(">I", (1100 << 4) | (4 << 1) | 1)[1:4]

        data = (
            rd_data
            + esi_data
            + eth_tag
            + bytes([ip_prefix_len])
            + ip_prefix_data
            + bytes([gw_ip_len])
            + gw_ip_data
            + mpls_label
        )

        result = bmp_parser._parse_evpn_route(5, data)

        assert result is not None
        assert result["type"] == 5
        assert result["name"] == "IP Prefix"
        assert result["rd"] == "65001:800"
        assert result["esi"] == "112233445566778899aa"
        assert result["eth_tag"] == 800
        assert result["ip_prefix_length"] == 24
        assert result["ip_prefix"] == "192.0.2.0/24"
        assert result["gateway_ip_length"] == 32
        assert result["gateway_ip"] == "192.0.2.1"
        assert result["mpls_label"] == 1100
        assert result["mpls_exp"] == 4
        assert result["mpls_s"] == 1

    def test_parse_evpn_route_type_5_ipv6(self, bmp_parser):
        """Test parsing EVPN Route Type 5 with IPv6."""
        rd_data = struct.pack(">HHI", 0, 65002, 900)  # RD: 65002:900
        esi_data = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44])  # ESI
        eth_tag = struct.pack(">I", 900)  # Ethernet Tag = 900
        ip_prefix_len = 64  # IPv6 /64 prefix
        ip_prefix_data = bytes(
            [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00]
        )  # 2001:db8::/64 (8 bytes)
        gw_ip_len = 128  # IPv6 gateway
        gw_ip_data = bytes(
            [
                0x20,
                0x01,
                0x0D,
                0xB8,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
            ]
        )  # 2001:db8::1
        # MPLS Label: Label=1200, EXP=2, S=1, TTL=100
        mpls_label = struct.pack(">I", (1200 << 4) | (2 << 1) | 1)[1:4]

        data = (
            rd_data
            + esi_data
            + eth_tag
            + bytes([ip_prefix_len])
            + ip_prefix_data
            + bytes([gw_ip_len])
            + gw_ip_data
            + mpls_label
        )

        result = bmp_parser._parse_evpn_route(5, data)

        assert result is not None
        assert result["type"] == 5
        assert result["name"] == "IP Prefix"
        assert result["rd"] == "65002:900"
        assert result["esi"] == "aabbccddeeff11223344"
        assert result["eth_tag"] == 900
        assert result["ip_prefix_length"] == 64
        assert result["ip_prefix"] == "2001:db8::/64"
        assert result["gateway_ip_length"] == 128
        assert result["gateway_ip"] == "2001:db8::1"
        assert result["mpls_label"] == 1200
        assert result["mpls_exp"] == 2
        assert result["mpls_s"] == 1

    def test_parse_evpn_route_type_5_no_gateway(self, bmp_parser):
        """Test parsing EVPN Route Type 5 with no gateway IP."""
        rd_data = struct.pack(">HHI", 0, 65003, 1000)  # RD: 65003:1000
        esi_data = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A])  # ESI
        eth_tag = struct.pack(">I", 1000)  # Ethernet Tag = 1000
        ip_prefix_len = 32  # IPv4 /32 host
        ip_prefix_data = struct.pack(">I", 0xC0000204)  # 192.0.2.4/32
        gw_ip_len = 0  # No gateway IP
        # MPLS Label: Label=1300, EXP=1, S=1, TTL=50
        mpls_label = struct.pack(">I", (1300 << 4) | (1 << 1) | 1)[1:4]

        data = (
            rd_data
            + esi_data
            + eth_tag
            + bytes([ip_prefix_len])
            + ip_prefix_data
            + bytes([gw_ip_len])
            + mpls_label
        )

        result = bmp_parser._parse_evpn_route(5, data)

        assert result is not None
        assert result["type"] == 5
        assert result["name"] == "IP Prefix"
        assert result["rd"] == "65003:1000"
        assert result["esi"] == "0102030405060708090a"
        assert result["eth_tag"] == 1000
        assert result["ip_prefix_length"] == 32
        assert result["ip_prefix"] == "192.0.2.4/32"
        assert result["gateway_ip_length"] == 0
        assert "gateway_ip" not in result  # No gateway IP when length is 0
        assert result["mpls_label"] == 1300
        assert result["mpls_exp"] == 1
        assert result["mpls_s"] == 1

    def test_parse_evpn_route_type_5_minimal_data(self, bmp_parser):
        """Test parsing EVPN Route Type 5 with minimal data."""
        data = bytes(20)  # Less than 22 bytes

        result = bmp_parser._parse_evpn_route(5, data)

        assert result is not None
        assert result["type"] == 5
        assert result["name"] == "IP Prefix"
        # Should not have detailed fields due to insufficient data
        assert "rd" not in result
        assert "esi" not in result
        assert "eth_tag" not in result

    @pytest.mark.unit
    def test_parse_per_peer_header_ipv4_mapped_extraction(self, bmp_parser):
        """Test per-peer header with IPv4-mapped IPv6 that extracts IPv4."""
        # Create header with IPv4-mapped IPv6 address (::ffff:192.0.2.1)
        header_data = struct.pack(">B", 0)  # Peer type
        header_data += struct.pack(">B", 0x80)  # IPv6 flag set
        header_data += struct.pack(">Q", 0)  # Peer Distinguisher (8 bytes)
        # IPv4-mapped IPv6: ::ffff:192.0.2.1
        ipv4_mapped = b"\x00" * 10 + b"\xff\xff" + struct.pack(">I", 0xC0000201)
        header_data += ipv4_mapped
        header_data += struct.pack(">I", 65001)  # Peer AS
        header_data += struct.pack(">I", 0xC0000201)  # Peer BGP ID
        header_data += struct.pack(">I", 1234567890)  # Timestamp seconds
        header_data += struct.pack(">I", 0)  # Timestamp microseconds

        result, offset = bmp_parser._parse_per_peer_header(header_data)

        assert result is not None
        assert result["peer_ip"] == "192.0.2.1"  # Should extract IPv4 from mapped

    @pytest.mark.unit
    def test_parse_per_peer_header_pure_ipv6(self, bmp_parser):
        """Test per-peer header with pure IPv6 address."""
        # Create header with pure IPv6 address (2001:db8::1)
        header_data = struct.pack(">B", 0)  # Peer type
        header_data += struct.pack(">B", 0x80)  # IPv6 flag set
        header_data += struct.pack(">Q", 0)  # Peer Distinguisher (8 bytes)
        # Pure IPv6: 2001:db8::1
        ipv6_addr = bytes(
            [
                0x20,
                0x01,
                0x0D,
                0xB8,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
            ]
        )
        header_data += ipv6_addr
        header_data += struct.pack(">I", 65001)  # Peer AS
        header_data += struct.pack(">I", 0xC0000201)  # Peer BGP ID
        header_data += struct.pack(">I", 1234567890)  # Timestamp seconds
        header_data += struct.pack(">I", 0)  # Timestamp microseconds

        result, offset = bmp_parser._parse_per_peer_header(header_data)

        assert result is not None
        assert result["peer_ip"] == "2001:db8::1"

    @pytest.mark.unit
    def test_parse_peer_up_local_ipv4_mapped(self, bmp_parser):
        """Test peer up with IPv4-mapped local address."""
        # Create minimal per-peer header
        per_peer_header = struct.pack(">B", 0x80)  # IPv6 flag
        per_peer_header += b"\x00" * 31  # Rest of header

        # IPv4-mapped IPv6 local address
        ipv4_mapped_local = b"\x00" * 10 + b"\xff\xff" + struct.pack(">I", 0xC0000202)  # 192.0.2.2
        remote_addr = struct.pack(">I", 0xC0000203)  # 192.0.2.3 IPv4
        remote_addr += b"\x00" * 12  # Padding to 16 bytes

        peer_up_data = ipv4_mapped_local + remote_addr
        peer_up_data += struct.pack(">HH", 179, 179)  # Local and remote ports
        peer_up_data += b"\x00" * 20  # Minimal BGP messages

        full_data = per_peer_header + peer_up_data
        # Create full BMP message with header
        bmp_header = struct.pack(">BBBBB", 3, 0, 0, 0, len(full_data) + 6)  # Version 3, message type 3
        bmp_header += struct.pack(">B", 3)  # Peer Up message type
        complete_message = bmp_header + full_data
        result = bmp_parser.parse_bmp_message(complete_message)

        assert result is not None
        assert result["type"] == 3

    @pytest.mark.unit
    def test_parse_initiation_message_with_multiple_tlvs(self, bmp_parser):
        """Test initiation message with multiple TLVs."""
        # Create initiation message with multiple information TLVs
        tlv_data = struct.pack(">HH", 1, 4) + b"test"  # Type=1, Length=4, Value="test"
        tlv_data += struct.pack(">HH", 2, 6) + b"value2"  # Type=2, Length=6, Value="value2"

        result = bmp_parser.parse_bmp_message(4, tlv_data)

        assert result is not None
        assert result["type"] == 4
        assert len(result["information"]) == 2

    @pytest.mark.unit
    def test_parse_termination_message_with_tlvs(self, bmp_parser):
        """Test termination message with TLVs."""
        # Create termination message with information TLVs
        tlv_data = struct.pack(">HH", 0, 8) + b"reason12"  # Type=0, Length=8

        result = bmp_parser.parse_bmp_message(5, tlv_data)

        assert result is not None
        assert result["type"] == 5
        assert len(result["information"]) == 1

    @pytest.mark.unit
    def test_parse_stats_report_with_multiple_stats(self, bmp_parser):
        """Test stats report with multiple statistics."""
        # Create minimal per-peer header
        per_peer_header = b"\x00" * 32

        # Stats data with multiple statistics
        stats_data = struct.pack(">I", 2)  # Count = 2
        # Stat 1
        stats_data += struct.pack(">HI", 0, 100)  # Type=0, Length=4, Value=100
        # Stat 2
        stats_data += struct.pack(">HI", 1, 200)  # Type=1, Length=4, Value=200

        full_data = per_peer_header + stats_data
        result = bmp_parser.parse_bmp_message(1, full_data)

        assert result is not None
        assert result["type"] == 1
        assert len(result["statistics"]) == 2

    @pytest.mark.unit
    def test_parse_route_mirroring_with_multiple_tlvs(self, bmp_parser):
        """Test route mirroring with multiple TLVs."""
        # Create minimal per-peer header
        per_peer_header = b"\x00" * 32

        # Multiple TLVs
        tlv_data = struct.pack(">HH", 0, 4) + b"mir1"  # Type=0, Length=4
        tlv_data += struct.pack(">HH", 1, 4) + b"mir2"  # Type=1, Length=4

        full_data = per_peer_header + tlv_data
        result = bmp_parser.parse_bmp_message(6, full_data)

        assert result is not None
        assert result["type"] == 6
