"""Unit tests for EVPN parser."""
import struct
from unittest.mock import patch

import pytest

from src.bmp.evpn_parser import EVPNParser
from src.bmp.parsing_utils import ParseError


class TestEVPNParser:
    """Test EVPN parser functionality."""

    @pytest.fixture
    def evpn_parser(self):
        """Create EVPN parser instance."""
        return EVPNParser()

    @pytest.mark.unit
    def test_parse_evpn_route_unknown_type(self, evpn_parser):
        """Test parsing unknown EVPN route type."""
        data = bytes(10)
        result = evpn_parser.parse_evpn_route(99, data)

        assert result is not None
        assert result["type"] == 99
        assert result["name"] == "Unknown"

    @pytest.mark.unit
    def test_parse_evpn_route_type_1_complete(self, evpn_parser):
        """Test parsing complete EVPN Route Type 1."""
        # Construct complete Route Type 1 data
        rd_data = struct.pack(">HHI", 0, 65001, 100)  # RD: 65001:100
        esi_data = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x02])  # ESI
        eth_tag = struct.pack(">I", 100)  # Ethernet Tag = 100
        # MPLS Label: Label=1000, EXP=3, S=1
        mpls_field_24bit = (1000 << 4) | (3 << 1) | 1
        mpls_label = struct.pack(">I", mpls_field_24bit)[1:]  # Take last 3 bytes

        data = rd_data + esi_data + eth_tag + mpls_label
        result = evpn_parser.parse_evpn_route(1, data)

        assert result is not None
        assert result["type"] == 1
        assert result["name"] == "Ethernet Auto-Discovery"
        assert result["rd"] == "65001:100"
        assert result["esi"] == "0123456789abcdef0102"
        assert result["eth_tag"] == 100
        assert result["mpls_label"] == 1000
        assert result["mpls_exp"] == 3
        assert result["mpls_s"] == 1

    @pytest.mark.unit
    def test_parse_evpn_route_type_1_insufficient_data(self, evpn_parser):
        """Test parsing Route Type 1 with insufficient data."""
        data = bytes(10)  # Less than 25 bytes required
        result = evpn_parser.parse_evpn_route(1, data)

        assert result is not None
        assert result["type"] == 1
        assert result["name"] == "Ethernet Auto-Discovery"
        assert "error" in result
        assert "data" in result

    @pytest.mark.unit
    def test_parse_evpn_route_type_2_complete(self, evpn_parser):
        """Test parsing complete EVPN Route Type 2."""
        # Construct Route Type 2 data
        rd_data = struct.pack(">HHI", 0, 65001, 200)  # RD: 65001:200
        esi_data = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA])  # ESI
        eth_tag = struct.pack(">I", 200)  # Ethernet Tag = 200
        mac_len = 48  # MAC length in bits
        mac_data = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])  # MAC address
        ip_len = 32  # IPv4 length in bits
        ipv4_data = struct.pack(">I", 0xC0000201)  # 192.0.2.1
        # MPLS Label 1: Label=2000, EXP=4, S=0
        mpls1_field = (2000 << 4) | (4 << 1) | 0
        mpls1_label = struct.pack(">I", mpls1_field)[1:]
        # MPLS Label 2: Label=3000, EXP=5, S=1
        mpls2_field = (3000 << 4) | (5 << 1) | 1
        mpls2_label = struct.pack(">I", mpls2_field)[1:]

        data = (
            rd_data
            + esi_data
            + eth_tag
            + bytes([mac_len])
            + mac_data
            + bytes([ip_len])
            + ipv4_data
            + mpls1_label
            + mpls2_label
        )
        result = evpn_parser.parse_evpn_route(2, data)

        assert result is not None
        assert result["type"] == 2
        assert result["name"] == "MAC/IP Advertisement"
        assert result["rd"] == "65001:200"
        assert result["esi"] == "112233445566778899aa"
        assert result["eth_tag"] == 200
        assert result["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["ip_length"] == 32
        assert result["ip_address"] == "192.0.2.1"
        assert result["mpls_label1"] == 2000
        assert result["mpls_exp1"] == 4
        assert result["mpls_s1"] == 0
        assert result["mpls_label2"] == 3000
        assert result["mpls_exp2"] == 5
        assert result["mpls_s2"] == 1

    @pytest.mark.unit
    def test_parse_evpn_route_type_2_invalid_mac_length(self, evpn_parser):
        """Test parsing Route Type 2 with invalid MAC length."""
        rd_data = struct.pack(">HHI", 0, 65001, 200)
        esi_data = bytes(10)
        eth_tag = struct.pack(">I", 200)
        mac_len = 64  # Invalid MAC length (should be 48)

        data = rd_data + esi_data + eth_tag + bytes([mac_len])
        result = evpn_parser.parse_evpn_route(2, data)

        assert result is not None
        assert result["type"] == 2
        assert result["name"] == "MAC/IP Advertisement"
        # Should not have MAC field with invalid length

    @pytest.mark.unit
    def test_parse_evpn_route_type_3_complete(self, evpn_parser):
        """Test parsing complete EVPN Route Type 3."""
        # Construct Route Type 3 data
        rd_data = struct.pack(">HHI", 0, 65001, 300)  # RD: 65001:300
        eth_tag = struct.pack(">I", 300)  # Ethernet Tag = 300
        ip_len = 32  # IPv4 length in bits
        ipv4_data = struct.pack(">I", 0xC0000203)  # 192.0.2.3

        data = rd_data + eth_tag + bytes([ip_len]) + ipv4_data
        result = evpn_parser.parse_evpn_route(3, data)

        assert result is not None
        assert result["type"] == 3
        assert result["name"] == "Inclusive Multicast"
        assert result["rd"] == "65001:300"
        assert result["eth_tag"] == 300
        assert result["ip_length"] == 32
        assert result["originating_ip"] == "192.0.2.3"

    @pytest.mark.unit
    def test_parse_evpn_route_type_3_ipv6(self, evpn_parser):
        """Test parsing Route Type 3 with IPv6."""
        rd_data = struct.pack(">HHI", 0, 65002, 300)
        eth_tag = struct.pack(">I", 300)
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
        result = evpn_parser.parse_evpn_route(3, data)

        assert result is not None
        assert result["type"] == 3
        assert result["name"] == "Inclusive Multicast"
        assert result["originating_ip"] == "2001:db8::2"

    @pytest.mark.unit
    def test_parse_evpn_route_type_4_complete(self, evpn_parser):
        """Test parsing complete EVPN Route Type 4."""
        # Construct Route Type 4 data
        rd_data = struct.pack(">HHI", 0, 65001, 400)  # RD: 65001:400
        esi_data = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x02])  # ESI
        ip_len = 32  # IPv4 length in bits
        ipv4_data = struct.pack(">I", 0xC0000204)  # 192.0.2.4

        data = rd_data + esi_data + bytes([ip_len]) + ipv4_data
        result = evpn_parser.parse_evpn_route(4, data)

        assert result is not None
        assert result["type"] == 4
        assert result["name"] == "Ethernet Segment"
        assert result["rd"] == "65001:400"
        assert result["esi"] == "0123456789abcdef0102"
        assert result["ip_length"] == 32
        assert result["originating_ip"] == "192.0.2.4"

    @pytest.mark.unit
    def test_parse_evpn_route_type_5_complete(self, evpn_parser):
        """Test parsing complete EVPN Route Type 5."""
        # Construct Route Type 5 data
        rd_data = struct.pack(">HHI", 0, 65001, 500)  # RD: 65001:500
        esi_data = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA])  # ESI
        eth_tag = struct.pack(">I", 500)  # Ethernet Tag = 500
        ip_prefix_len = 24  # IPv4 /24 prefix
        ip_prefix_data = bytes([192, 0, 2])  # 192.0.2.0/24
        gw_ip_len = 32  # Gateway IPv4 length
        gw_ipv4_data = struct.pack(">I", 0xC0000201)  # 192.0.2.1
        # MPLS Label: Label=5000, EXP=6, S=1
        mpls_field = (5000 << 4) | (6 << 1) | 1
        mpls_label = struct.pack(">I", mpls_field)[1:]

        data = (
            rd_data
            + esi_data
            + eth_tag
            + bytes([ip_prefix_len])
            + ip_prefix_data
            + bytes([gw_ip_len])
            + gw_ipv4_data
            + mpls_label
        )
        result = evpn_parser.parse_evpn_route(5, data)

        assert result is not None
        assert result["type"] == 5
        assert result["name"] == "IP Prefix"
        assert result["rd"] == "65001:500"
        assert result["esi"] == "112233445566778899aa"
        assert result["eth_tag"] == 500
        assert result["ip_prefix_length"] == 24
        assert result["ip_prefix"] == "192.0.2.0/24"
        assert result["gateway_ip_length"] == 32
        assert result["gateway_ip"] == "192.0.2.1"
        assert result["mpls_label"] == 5000
        assert result["mpls_exp"] == 6
        assert result["mpls_s"] == 1

    @pytest.mark.unit
    def test_parse_evpn_route_type_5_no_gateway(self, evpn_parser):
        """Test parsing Route Type 5 with no gateway IP."""
        rd_data = struct.pack(">HHI", 0, 65001, 500)
        esi_data = bytes(10)
        eth_tag = struct.pack(">I", 500)
        ip_prefix_len = 32  # IPv4 /32
        ip_prefix_data = struct.pack(">I", 0xC0000205)  # 192.0.2.5/32
        gw_ip_len = 0  # No gateway IP
        # MPLS Label: Label=6000, EXP=7, S=1
        mpls_field = (6000 << 4) | (7 << 1) | 1
        mpls_label = struct.pack(">I", mpls_field)[1:]

        data = (
            rd_data
            + esi_data
            + eth_tag
            + bytes([ip_prefix_len])
            + ip_prefix_data
            + bytes([gw_ip_len])
            + mpls_label
        )
        result = evpn_parser.parse_evpn_route(5, data)

        assert result is not None
        assert result["type"] == 5
        assert result["name"] == "IP Prefix"
        assert result["ip_prefix"] == "192.0.2.5/32"
        assert result["gateway_ip_length"] == 0
        assert "gateway_ip" not in result  # No gateway IP when length is 0
        assert result["mpls_label"] == 6000

    @pytest.mark.unit
    def test_parse_evpn_route_exception_handling(self, evpn_parser):
        """Test exception handling in EVPN route parsing."""
        # Mock a parsing function to raise an exception
        with patch.object(
            evpn_parser, "_parse_ethernet_auto_discovery", side_effect=Exception("Test error")
        ):
            result = evpn_parser.parse_evpn_route(1, bytes(30))
            assert result is None

    @pytest.mark.unit
    def test_parse_evpn_route_parse_error_handling(self, evpn_parser):
        """Test ParseError handling in EVPN route parsing."""
        # Create data that will trigger ParseError due to insufficient length
        insufficient_data = bytes(5)  # Too short for any route type

        for route_type in [1, 2, 3, 4, 5]:
            result = evpn_parser.parse_evpn_route(route_type, insufficient_data)
            assert result is not None
            assert result["type"] == route_type
            assert "error" in result
            assert "data" in result
            assert result["data"] == insufficient_data.hex()

    @pytest.mark.unit
    def test_parse_evpn_route_type_names(self, evpn_parser):
        """Test correct type names for all EVPN route types."""
        type_names = {
            1: "Ethernet Auto-Discovery",
            2: "MAC/IP Advertisement",
            3: "Inclusive Multicast",
            4: "Ethernet Segment",
            5: "IP Prefix",
        }

        # Test with insufficient data to trigger ParseError and get type names
        insufficient_data = bytes(5)

        for route_type, expected_name in type_names.items():
            result = evpn_parser.parse_evpn_route(route_type, insufficient_data)
            assert result is not None
            assert result["type"] == route_type
            assert result["name"] == expected_name


class TestEVPNParserEdgeCases:
    """Test edge cases and boundary conditions for EVPN parser."""

    @pytest.fixture
    def evpn_parser(self):
        """Create EVPN parser instance."""
        return EVPNParser()

    @pytest.mark.unit
    def test_parse_evpn_route_type_1_exact_minimum(self, evpn_parser):
        """Test parsing Route Type 1 with exactly minimum required data."""
        data = bytes(25)  # Exactly 25 bytes
        result = evpn_parser.parse_evpn_route(1, data)

        assert result is not None
        assert result["type"] == 1
        assert result["name"] == "Ethernet Auto-Discovery"
        assert "rd" in result
        assert "esi" in result
        assert "eth_tag" in result
        assert "mpls_label" in result

    @pytest.mark.unit
    def test_parse_evpn_route_type_2_no_ip_address(self, evpn_parser):
        """Test parsing Route Type 2 with no IP address."""
        rd_data = struct.pack(">HHI", 0, 65001, 200)
        esi_data = bytes(10)
        eth_tag = struct.pack(">I", 200)
        mac_len = 48
        mac_data = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        ip_len = 0  # No IP address

        data = rd_data + esi_data + eth_tag + bytes([mac_len]) + mac_data + bytes([ip_len])
        result = evpn_parser.parse_evpn_route(2, data)

        assert result is not None
        assert result["type"] == 2
        assert result["name"] == "MAC/IP Advertisement"
        assert result["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["ip_length"] == 0
        assert "ip_address" not in result

    @pytest.mark.unit
    def test_parse_evpn_route_type_3_zero_ip_length(self, evpn_parser):
        """Test parsing Route Type 3 with zero IP length."""
        rd_data = struct.pack(">HHI", 0, 65001, 300)
        eth_tag = struct.pack(">I", 300)
        ip_len = 0  # No IP address

        data = rd_data + eth_tag + bytes([ip_len])
        result = evpn_parser.parse_evpn_route(3, data)

        assert result is not None
        assert result["type"] == 3
        assert result["name"] == "Inclusive Multicast"
        assert result["ip_length"] == 0
        assert "originating_ip" not in result

    @pytest.mark.unit
    def test_parse_evpn_route_type_4_minimal_data(self, evpn_parser):
        """Test parsing Route Type 4 with exactly minimal data."""
        data = bytes(18)  # Exactly 18 bytes (RD + ESI)
        result = evpn_parser.parse_evpn_route(4, data)

        assert result is not None
        assert result["type"] == 4
        assert result["name"] == "Ethernet Segment"
        assert "rd" in result
        assert "esi" in result
        # No IP-related fields since no IP data

    @pytest.mark.unit
    def test_parse_evpn_route_type_5_partial_data(self, evpn_parser):
        """Test parsing Route Type 5 with partial data."""
        rd_data = struct.pack(">HHI", 0, 65001, 500)
        esi_data = bytes(10)
        eth_tag = struct.pack(">I", 500)
        ip_prefix_len = 24
        ip_prefix_data = bytes([192, 0, 2])
        # No gateway IP or MPLS label

        data = rd_data + esi_data + eth_tag + bytes([ip_prefix_len]) + ip_prefix_data
        result = evpn_parser.parse_evpn_route(5, data)

        assert result is not None
        assert result["type"] == 5
        assert result["name"] == "IP Prefix"
        assert result["ip_prefix_length"] == 24
        assert result["ip_prefix"] == "192.0.2.0/24"
        # Should not have gateway or MPLS fields
        assert "gateway_ip" not in result
        assert "mpls_label" not in result

    @pytest.mark.unit
    def test_parse_evpn_route_empty_data(self, evpn_parser):
        """Test parsing with empty data."""
        for route_type in [1, 2, 3, 4, 5]:
            result = evpn_parser.parse_evpn_route(route_type, b"")
            assert result is not None
            assert result["type"] == route_type
            assert "error" in result

    @pytest.mark.unit
    def test_parse_evpn_route_very_large_data(self, evpn_parser):
        """Test parsing with very large data payload."""
        # Create data much larger than needed for Route Type 1
        large_data = bytes(1000)
        result = evpn_parser.parse_evpn_route(1, large_data)

        assert result is not None
        assert result["type"] == 1
        assert result["name"] == "Ethernet Auto-Discovery"
        # Should parse successfully despite extra data
