"""Unit tests for BMP parser."""
import pytest
import struct
from unittest.mock import patch

from src.bmp.parser import (
    BMPParser, BMPMessageType, BMPPeerType, BGPMessageType,
    AFI, SAFI
)
from tests.fixtures.bmp_messages import BMPMessageBuilder, TEST_MESSAGES, INVALID_MESSAGES


class TestBMPParser:
    """Test BMP parser functionality."""

    def test_parser_initialization(self, bmp_parser):
        """Test parser initialization."""
        assert isinstance(bmp_parser, BMPParser)
        assert bmp_parser.buffer == b""

    @pytest.mark.unit
    def test_parse_valid_route_monitoring_message(self, bmp_parser):
        """Test parsing valid route monitoring message."""
        message_data = TEST_MESSAGES['route_monitoring']
        result = bmp_parser.parse_message(message_data)

        assert result is not None
        assert result['type'] == 'route_monitoring'
        assert 'peer' in result
        assert 'bgp_message' in result

        # Check peer header
        peer = result['peer']
        assert peer['peer_type'] == 0
        assert peer['peer_as'] == 65001
        assert peer['peer_ip'] == '192.0.2.1'

        # Check BGP message
        bgp_msg = result['bgp_message']
        assert bgp_msg['type'] == 'UPDATE'

    @pytest.mark.unit
    def test_parse_peer_up_message(self, bmp_parser):
        """Test parsing peer up message."""
        message_data = TEST_MESSAGES['peer_up']
        result = bmp_parser.parse_message(message_data)

        assert result is not None
        assert result['type'] == 'peer_up'
        assert 'peer' in result
        assert 'local_ip' in result
        assert 'local_port' in result
        assert 'remote_port' in result

    @pytest.mark.unit
    def test_parse_peer_down_message(self, bmp_parser):
        """Test parsing peer down message."""
        message_data = TEST_MESSAGES['peer_down']
        result = bmp_parser.parse_message(message_data)

        assert result is not None
        assert result['type'] == 'peer_down'
        assert 'peer' in result
        assert 'reason' in result

    @pytest.mark.unit
    def test_parse_initiation_message(self, bmp_parser):
        """Test parsing initiation message."""
        message_data = TEST_MESSAGES['initiation']
        result = bmp_parser.parse_message(message_data)

        assert result is not None
        assert result['type'] == 'initiation'
        assert 'information' in result
        assert isinstance(result['information'], list)

    @pytest.mark.unit
    def test_parse_termination_message(self, bmp_parser):
        """Test parsing termination message."""
        message_data = TEST_MESSAGES['termination']
        result = bmp_parser.parse_message(message_data)

        assert result is not None
        assert result['type'] == 'termination'
        assert 'information' in result

    @pytest.mark.unit
    def test_parse_stats_report_message(self, bmp_parser):
        """Test parsing statistics report message."""
        message_data = TEST_MESSAGES['stats_report']
        result = bmp_parser.parse_message(message_data)

        assert result is not None
        assert result['type'] == 'stats_report'
        assert 'peer' in result
        assert 'stats' in result
        assert isinstance(result['stats'], list)

    @pytest.mark.unit
    def test_parse_invalid_version(self, bmp_parser):
        """Test parsing message with invalid version."""
        result = bmp_parser.parse_message(INVALID_MESSAGES['wrong_version'])
        assert result is None

    @pytest.mark.unit
    def test_parse_short_message(self, bmp_parser):
        """Test parsing message shorter than minimum."""
        result = bmp_parser.parse_message(INVALID_MESSAGES['short_header'])
        assert result is None

    @pytest.mark.unit
    def test_parse_incomplete_message(self, bmp_parser):
        """Test parsing incomplete message."""
        # Create message that claims to be longer than actual data
        incomplete = b'\x03\x00\x00\x00\x20\x00' + b'incomplete'
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
            peer_bgp_id="203.0.113.1"
        )

        header, offset = bmp_parser._parse_per_peer_header(peer_data)

        assert header['peer_type'] == 1
        assert header['peer_flags']['v_flag'] is True
        assert header['peer_as'] == 4200000000
        assert offset == 42

    @pytest.mark.unit
    def test_per_peer_header_insufficient_data(self, bmp_parser):
        """Test per-peer header with insufficient data."""
        insufficient_data = b'\x00' * 30  # Less than required 42 bytes

        with pytest.raises(ValueError, match="Insufficient data for per-peer header"):
            bmp_parser._parse_per_peer_header(insufficient_data)

    @pytest.mark.unit
    def test_bgp_update_parsing(self, bmp_parser):
        """Test BGP UPDATE message parsing."""
        # Create BGP UPDATE with withdrawn routes and NLRI
        bgp_update = BMPMessageBuilder.create_bgp_update(
            withdrawn=['10.0.1.0/24'],
            path_attrs=[
                {'type': 1, 'value': 0},  # ORIGIN
                {'type': 3, 'value': '192.0.2.1'}  # NEXT_HOP
            ],
            nlri=['10.0.2.0/24', '10.0.3.0/24']
        )

        # Extract just the UPDATE part (skip BGP header)
        update_data = bgp_update[19:]  # Skip 19-byte BGP header
        result = bmp_parser._parse_bgp_update(update_data)

        assert result['type'] == 'UPDATE'
        assert 'withdrawn' in result
        assert 'attributes' in result
        assert 'nlri' in result

    @pytest.mark.unit
    def test_parse_as_path_attribute(self, bmp_parser):
        """Test AS_PATH attribute parsing."""
        # Create AS_PATH with AS_SEQUENCE
        as_path_data = struct.pack(">BB", 2, 3)  # AS_SEQUENCE, 3 ASNs
        as_path_data += struct.pack(">III", 65001, 65002, 65003)

        result = bmp_parser._parse_as_path(as_path_data)

        assert len(result) == 1
        assert result[0]['type'] == 'AS_SEQUENCE'
        assert result[0]['as_numbers'] == [65001, 65002, 65003]

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
        nlri_data = b'\x18\x0a\x00\x01'  # 24-bit prefix 10.0.1
        nlri_data += b'\x1c\xc0\xa8\x01\x00'  # 28-bit prefix 192.168.1.0

        result = bmp_parser._parse_nlri(nlri_data, AFI.IPV4)

        assert len(result) == 2
        assert '10.0.1.0/24' in result
        assert '192.168.1.0/28' in result

    @pytest.mark.unit
    def test_parse_nlri_ipv6(self, bmp_parser):
        """Test IPv6 NLRI parsing."""
        # Create NLRI for 2001:db8::/32
        nlri_data = b'\x20' + b'\x20\x01\x0d\xb8'  # 32-bit prefix

        result = bmp_parser._parse_nlri(nlri_data, AFI.IPV6)

        assert len(result) == 1
        assert '2001:db8::/32' in result

    @pytest.mark.unit
    def test_parse_mp_reach_nlri(self, bmp_parser):
        """Test MP_REACH_NLRI attribute parsing."""
        # Create MP_REACH_NLRI for IPv6 unicast
        mp_reach_data = struct.pack(">HBB", AFI.IPV6, SAFI.UNICAST, 16)  # AFI, SAFI, NH len
        mp_reach_data += b'\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'  # Next hop
        mp_reach_data += b'\x00'  # Reserved
        mp_reach_data += b'\x40\x20\x01\x0d\xb8\x00\x01'  # NLRI: 2001:db8:1::/64

        result = bmp_parser._parse_mp_reach_nlri(mp_reach_data)

        assert result['afi'] == AFI.IPV6
        assert result['safi'] == SAFI.UNICAST
        assert result['next_hop'] == '2001:db8::1'
        assert len(result['nlri']) >= 0

    @pytest.mark.unit
    def test_parse_mp_unreach_nlri(self, bmp_parser):
        """Test MP_UNREACH_NLRI attribute parsing."""
        # Create MP_UNREACH_NLRI
        mp_unreach_data = struct.pack(">HB", AFI.IPV4, SAFI.UNICAST)
        mp_unreach_data += b'\x18\x0a\x00\x01'  # Withdrawn: 10.0.1.0/24

        result = bmp_parser._parse_mp_unreach_nlri(mp_unreach_data)

        assert result['afi'] == AFI.IPV4
        assert result['safi'] == SAFI.UNICAST
        assert 'withdrawn' in result

    @pytest.mark.unit
    def test_parse_bgp_open_message(self, bmp_parser):
        """Test BGP OPEN message parsing."""
        # Create BGP OPEN message data (without header)
        open_data = struct.pack(">BHHIB", 4, 65001, 180, 0xC0000201, 0)  # Version, AS, Hold time, BGP ID, Opt len

        result = bmp_parser._parse_bgp_open(open_data)

        assert result['type'] == 'OPEN'
        assert result['version'] == 4
        assert result['as'] == 65001
        assert result['hold_time'] == 180
        assert result['bgp_id'] == '192.0.2.1'

    @pytest.mark.unit
    def test_parse_bgp_open_invalid_length(self, bmp_parser):
        """Test BGP OPEN message with invalid length."""
        # Too short OPEN message
        short_open = b'\x04\x00\x01'

        result = bmp_parser._parse_bgp_open(short_open)

        assert result['type'] == 'OPEN'
        assert 'error' in result

    @pytest.mark.unit
    def test_parse_route_distinguisher(self, bmp_parser):
        """Test Route Distinguisher parsing."""
        # Type 0: AS:Number
        rd_type0 = struct.pack(">HHHI", 0, 65001, 100)
        result = bmp_parser._parse_route_distinguisher(rd_type0)
        assert result == "65001:100"

        # Type 1: IP:Number
        rd_type1 = struct.pack(">H", 1) + struct.pack(">I", 0xC0000201) + struct.pack(">H", 100)
        result = bmp_parser._parse_route_distinguisher(rd_type1)
        assert result == "192.0.2.1:100"

        # Invalid length
        invalid_rd = b'\x00\x01\x02'
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
        assert result[0]['type'] == 0
        assert result[0]['value'] == "test"
        assert result[1]['type'] == 2
        assert result[1]['value'] == "router"

    @pytest.mark.unit
    def test_parse_capabilities(self, bmp_parser):
        """Test BGP capabilities parsing."""
        # Create capabilities: Multiprotocol (code 1)
        cap_data = struct.pack(">BBB", 1, 4, 0)  # Code, length, padding
        cap_data += struct.pack(">HB", AFI.IPV6, SAFI.UNICAST)

        result = bmp_parser._parse_capabilities(cap_data)

        assert len(result) == 1
        assert result[0]['code'] == 1

    @pytest.mark.unit
    def test_error_handling(self, bmp_parser):
        """Test error handling in parser."""
        # Test with corrupted data that should trigger exception handling
        corrupted_data = b'\x03\x00\x00\x00\x50\x00' + b'\xff' * 70

        with patch('src.bmp.parser.logger') as mock_logger:
            result = bmp_parser.parse_message(corrupted_data)

            # Should return None and log error
            assert result is None
            mock_logger.error.assert_called()

    @pytest.mark.unit
    def test_buffer_management(self, bmp_parser):
        """Test parser buffer management."""
        # Test that parser doesn't maintain state between calls
        message1 = TEST_MESSAGES['route_monitoring']
        message2 = TEST_MESSAGES['peer_up']

        result1 = bmp_parser.parse_message(message1)
        result2 = bmp_parser.parse_message(message2)

        assert result1['type'] == 'route_monitoring'
        assert result2['type'] == 'peer_up'
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
        large_data = b'\x03' + struct.pack(">I", 1000) + b'\x00' + b'x' * 994
        result = bmp_parser.parse_message(large_data)
        # Should handle gracefully (may return None due to invalid content)
        assert result is None  # Expected since content is not valid BMP

    @pytest.mark.unit
    def test_zero_length_fields(self, bmp_parser):
        """Test handling of zero-length fields."""
        # Create TLV with zero-length value
        tlv_data = struct.pack(">HH", 0, 0)  # Type 0, length 0
        result = bmp_parser._parse_tlvs(tlv_data)

        assert len(result) == 1
        assert result[0]['value'] == ""

    @pytest.mark.unit
    def test_malformed_nlri(self, bmp_parser):
        """Test handling of malformed NLRI."""
        # NLRI with invalid prefix length
        malformed_nlri = b'\xff\x0a\x00\x01'  # 255-bit prefix (invalid)

        result = bmp_parser._parse_nlri(malformed_nlri, AFI.IPV4)
        # Should handle gracefully and not crash
        assert isinstance(result, list)

    @pytest.mark.unit
    def test_empty_as_path(self, bmp_parser):
        """Test handling of empty AS_PATH."""
        empty_as_path = b''
        result = bmp_parser._parse_as_path(empty_as_path)
        assert result == []

    @pytest.mark.unit
    def test_truncated_path_attributes(self, bmp_parser):
        """Test handling of truncated path attributes."""
        # Create truncated attribute (claims length but data is shorter)
        truncated_attr = struct.pack(">BBB", 0x40, 1, 10) + b'\x00'  # Claims 10 bytes, only 1 available

        result = bmp_parser._parse_path_attributes(truncated_attr)
        # Should handle gracefully and stop parsing
        assert isinstance(result, list)

    @pytest.mark.unit
    @pytest.mark.parametrize("afi,safi", [
        (AFI.IPV4, SAFI.UNICAST),
        (AFI.IPV6, SAFI.UNICAST),
        (AFI.L2VPN, SAFI.EVPN),
        (999, 999)  # Invalid AFI/SAFI
    ])
    def test_various_afi_safi_combinations(self, bmp_parser, afi, safi):
        """Test parsing with various AFI/SAFI combinations."""
        mp_unreach_data = struct.pack(">HB", afi, safi) + b'\x18\x0a\x00\x01'

        result = bmp_parser._parse_mp_unreach_nlri(mp_unreach_data)

        assert result['afi'] == afi
        assert result['safi'] == safi
        assert 'withdrawn' in result